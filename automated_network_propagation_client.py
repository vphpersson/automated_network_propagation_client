#!/usr/bin/env python

from logging import getLogger, Logger, INFO
from logging.handlers import TimedRotatingFileHandler
from toml import loads as toml_loads
from typing import Final, Sequence
from asyncio import run as asyncio_run
from time import sleep
from ipaddress import ip_address, IPv4Address, IPv6Address
from json import loads as json_loads
from pathlib import Path
from subprocess import Popen

from ecs_tools_py import make_log_handler
from nftables import Nftables
from httpx import AsyncClient, ReadError
from httpx_sse import aconnect_sse
from stamina import retry
from redis.asyncio.client import Redis as RedisClient

from automated_network_propagation_client.cli import AutomatedNetworkPropagationClientOptionParser as \
    ANPCOP

LOG: Final[Logger] = getLogger(__name__)


def create_set_content(set_name: str, elements: Sequence[str], table_name: str = 'inet') -> str:
    return (
        f'add element {table_name} filter {set_name} {{ {",".join(elements)} }}'
        if elements else ''
    )


def create_dynamic_denylist_set_content(
    set_name: str,
    ip_address_ttl_value_pairs: list[tuple[str, int]],
    table_name: str = 'inet'
) -> str:
    """
    Create the NFT statement for populating the dynamic denylist set.

    :param set_name: The name of the dynamic denylist set.
    :param ip_address_ttl_value_pairs: Pairs of IP addresses and their corresponding timeout values.
    :param table_name: The name of the table in which the set is defined.
    :return: An NFT statement that populates the dynamic denylist set.
    """

    return (
        f'add element {table_name} filter {set_name} {{ {",".join(f"{ip_a} timeout {ttl}s" for ip_a, ttl in ip_address_ttl_value_pairs)} }}'
        if ip_address_ttl_value_pairs else ''
    )


async def write_dynamic_denylist_set(
    file_path: str,
    set_prefix: str,
    redis_key_prefix: str,
    redis_client: RedisClient
):
    """

    :param file_path:
    :param set_prefix:
    :param redis_key_prefix:
    :param redis_client:
    :return:
    """

    ipv4_address_ttl_value_pairs: list[tuple[str, int]] = []
    ipv6_address_ttl_value_pairs: list[tuple[str, int]] = []

    key: str
    async for key in redis_client.scan_iter(match=f'{redis_key_prefix}|*'):
        try:
            redis_key_ip_address: IPv4Address | IPv6Address = ip_address(address=key.removeprefix(f'{redis_key_prefix}|'))
        except ValueError:
            LOG.exception(
                msg='The Redis dynamic denylist key does not constitute an IP address',
                extra=dict(redis_key=key)
            )
            continue

        set_name_suffix: str
        if isinstance(redis_key_ip_address, IPv4Address):
            pair_ilst = ipv4_address_ttl_value_pairs
        elif isinstance(redis_key_ip_address, IPv6Address):
            pair_ilst = ipv6_address_ttl_value_pairs
        else:
            LOG.error(
                msg='A Redis dynamic denylist key does not seem to be either an IPv4 or IPv6 address. Should not happen.',
                extra=dict(redis_key=key)
            )
            continue

        pair_ilst.append(
            (
                key.removeprefix(f'{redis_key_prefix}|'),
                int(await redis_client.ttl(name=key))
            )
        )

    return Path(file_path).write_text(
        '\n'.join([
            create_dynamic_denylist_set_content(
                set_name=f'{set_prefix}_IPV4'.upper(),
                ip_address_ttl_value_pairs=ipv4_address_ttl_value_pairs
            ),
            create_dynamic_denylist_set_content(
                set_name=f'{set_prefix}_IPV6'.upper(),
                ip_address_ttl_value_pairs=ipv6_address_ttl_value_pairs
            )
        ])
    )


def write_set(file_path: str, set_prefix: str, data: dict[str, list[str]], key_prefix: str) -> int:
    return Path(file_path).write_text(
        '\n'.join([
            create_set_content(
                set_name=f'{set_prefix}_IPV4'.upper(),
                elements=data[f'{key_prefix}_ipv4']
            ),
            create_set_content(
                set_name=f'{set_prefix}_IPV6'.upper(),
                elements=data[f'{key_prefix}_ipv6']
            )
        ])
    )


def aiter_sse_retrying(client: AsyncClient):
    last_event_id = ''
    reconnection_delay = 0.0

    # `stamina` will apply jitter and exponential backoff on top of
    # the `retry` reconnection delay sent by the server.
    @retry(on=ReadError)
    async def _aiter_sse():
        nonlocal last_event_id, reconnection_delay

        sleep(reconnection_delay)

        headers = {'Accept': 'text/event-stream'}
        if last_event_id:
            headers['Last-Event-ID'] = last_event_id

        async with aconnect_sse(client=client, method='GET', url='http://localhost:8080/feed', headers=headers) as event_source:
            async for sse in event_source.aiter_sse():
                last_event_id = sse.id

                if sse.retry is not None:
                    reconnection_delay = sse.retry / 1000

                yield sse

    return _aiter_sse()


async def handle(
    http_client: AsyncClient,
    redis_client: RedisClient,
    nft_client: Nftables,
    config: dict[str, ...]
):
    """

    :param http_client: An HTTP client to be used in the SSE connection.
    :param redis_client: A Redis client for persisting the dynamic block list.
    :param nft_client: An NFT client for inserting dynamic block rules.
    :param config: A configuration storing paths, names, e.g.
    :return:
    """

    dynamic_denylist_config = config['dynamic_denylist']

    async for sse in aiter_sse_retrying(client=http_client):
        match sse.event:
            case 'block':
                try:
                    block_ip_address: IPv4Address | IPv6Address = ip_address(address=sse.data)
                except ValueError:
                    LOG.exception(
                        msg='The provided block SSE data does not constitute an IP address',
                        extra=dict(sse_data=sse.data)
                    )
                    continue

                set_name_suffix: str
                if isinstance(block_ip_address, IPv4Address):
                    set_name_suffix = '_IPV4'
                elif isinstance(block_ip_address, IPv6Address):
                    set_name_suffix = '_IPV6'
                else:
                    LOG.error(
                        msg='The block IP address does not seem to be either an IPv4 or IPv6 address. Should not happen.',
                        extra=dict(sse_data=sse.data)
                    )
                    continue

                increment_key = f'{config["redis"]["increment_key_prefix"]}|{block_ip_address}'
                denylist_key = f'{config["redis"]["denylist_key_prefix"]}|{block_ip_address}'

                increment_num: int = int(await redis_client.incr(name=increment_key))

                expiry_times: list[int] = config['dynamic_denylist']['expiry_times']
                expiry_time_seconds: int = expiry_times[min(increment_num-1, len(expiry_times)-1)]

                async with redis_client.pipeline(transaction=True) as redis_pipe:
                    await redis_pipe.set(
                        name=denylist_key,
                        value=str(block_ip_address)
                    ).expire(
                        name=denylist_key,
                        time=expiry_time_seconds
                    ).execute()

                nft_client.cmd(
                    cmdline=f'add element inet filter {config["dynamic_denylist"]["set_prefix"]}{set_name_suffix} {{ {block_ip_address} timeout {expiry_time_seconds}s }}'
                )
            case 'maxmind':
                try:
                    maxmind_data: dict[str, list[str]] = json_loads(sse.data)
                except Exception:
                    LOG.exception(msg='An error occurred when deserializing Maxmind data.')
                    continue

                # Geoblock

                maxmind_geoblock_config = config['maxmind']['geoblock']
                write_set(
                    file_path=maxmind_geoblock_config['path'],
                    set_prefix=maxmind_geoblock_config['set_prefix'],
                    data=maxmind_data,
                    key_prefix=maxmind_geoblock_config['key_prefix']
                )

                # Scanners

                maxmind_scanners_config = config['maxmind']['scanners']
                write_set(
                    file_path=maxmind_scanners_config['path'],
                    set_prefix=maxmind_scanners_config['set_prefix'],
                    data=maxmind_data,
                    key_prefix=maxmind_scanners_config['key_prefix']
                )

                # Data centers

                maxmind_data_centers_config = config['maxmind']['data_centers']
                write_set(
                    file_path=maxmind_data_centers_config['path'],
                    set_prefix=maxmind_data_centers_config['set_prefix'],
                    data=maxmind_data,
                    key_prefix=maxmind_data_centers_config['key_prefix']
                )

                await write_dynamic_denylist_set(
                    file_path=dynamic_denylist_config['path'],
                    set_prefix=dynamic_denylist_config['set_prefix'],
                    redis_key_prefix=config['redis']['denylist_key_prefix'],
                    redis_client=redis_client
                )
                Popen(args='systemctl restart nftables', shell=True).wait()
            case 'ripe':
                try:
                    ripe_data: dict[str, list[str]] = json_loads(sse.data)
                except Exception:
                    LOG.exception(msg='An error occurred when deserializing Ripe data.')
                    continue

                # Scanners

                ripe_scanners_config = config['ripe']['scanners']
                write_set(
                    file_path=ripe_scanners_config['path'],
                    set_prefix=ripe_scanners_config['set_prefix'],
                    data=ripe_data,
                    key_prefix=ripe_scanners_config['key_prefix']
                )

                await write_dynamic_denylist_set(
                    file_path=dynamic_denylist_config['path'],
                    set_prefix=dynamic_denylist_config['set_prefix'],
                    redis_key_prefix=config['redis']['denylist_key_prefix'],
                    redis_client=redis_client
                )
                Popen(args='systemctl restart nftables', shell=True).wait()
            case 'abuseipdb':
                try:
                    abuseipdb_data: dict[str, list[str]] = json_loads(sse.data)
                except Exception:
                    LOG.exception(msg='An error occurred when deserializing AbuseIPDB data.')
                    continue

                # Blacklist

                abuseipdb_blacklist_config = config['abuseipdb']['blacklist']
                write_set(
                    file_path=abuseipdb_blacklist_config['path'],
                    set_prefix=abuseipdb_blacklist_config['set_prefix'],
                    data=abuseipdb_data,
                    key_prefix=abuseipdb_blacklist_config['key_prefix']
                )

                await write_dynamic_denylist_set(
                    file_path=dynamic_denylist_config['path'],
                    set_prefix=dynamic_denylist_config['set_prefix'],
                    redis_key_prefix=config['redis']['denylist_key_prefix'],
                    redis_client=redis_client
                )
                Popen(args='systemctl restart nftables', shell=True).wait()
            case 'bing_bots':
                try:
                    bing_bots_data: dict[str, list[str]] = json_loads(sse.data)
                except Exception:
                    LOG.exception(msg='An error occurred when deserializing AbuseIPDB data.')
                    continue

                # Bing bots

                bing_bots_config = config['bing_bots']
                write_set(
                    file_path=bing_bots_config['path'],
                    set_prefix=bing_bots_config['set_prefix'],
                    data=bing_bots_data,
                    key_prefix=bing_bots_config['key_prefix']
                )

                await write_dynamic_denylist_set(
                    file_path=dynamic_denylist_config['path'],
                    set_prefix=dynamic_denylist_config['set_prefix'],
                    redis_key_prefix=config['redis']['denylist_key_prefix'],
                    redis_client=redis_client
                )
                Popen(args='systemctl restart nftables', shell=True).wait()
            case 'google_bots':
                try:
                    google_bots_data: dict[str, list[str]] = json_loads(sse.data)
                except Exception:
                    LOG.exception(msg='An error occurred when deserializing AbuseIPDB data.')
                    continue

                # Google bots

                google_bots_config = config['google_bots']
                write_set(
                    file_path=google_bots_config['path'],
                    set_prefix=google_bots_config['set_prefix'],
                    data=google_bots_data,
                    key_prefix=google_bots_config['key_prefix']
                )

                await write_dynamic_denylist_set(
                    file_path=dynamic_denylist_config['path'],
                    set_prefix=dynamic_denylist_config['set_prefix'],
                    redis_key_prefix=config['redis']['denylist_key_prefix'],
                    redis_client=redis_client
                )
                Popen(args='systemctl restart nftables', shell=True).wait()
            case _:
                LOG.warning(
                    msg='Unexpected SSE event.',
                    extra=dict(see_type=sse.event)
                )


async def main():
    try:
        args: ANPCOP.Namespace = ANPCOP().parse_options(read_config=False)

        log_handler = make_log_handler(
            base_class=TimedRotatingFileHandler,
            provider_name='automated_network_propagation_client',
            generate_field_names=('event.timezone', 'host.name', 'host.hostname')
        )(filename=args.log_path, when='D')

        LOG.addHandler(hdlr=log_handler)
        LOG.setLevel(level=INFO)

        config: dict[str, ...] = toml_loads(Path(args.config_path).read_text())

        nft_client = Nftables()

        async with (
            AsyncClient(timeout=None) as http_client,
            RedisClient(unix_socket_path=config['redis']['unix_socket_path']) as redis_client
        ):
            await handle(
                http_client=http_client,
                redis_client=redis_client,
                nft_client=nft_client,
                config=config
            )
    except KeyboardInterrupt:
        pass
    except Exception:
        LOG.exception(msg=f'An unexpected error occurred.')


if __name__ == '__main__':
    asyncio_run(main())
