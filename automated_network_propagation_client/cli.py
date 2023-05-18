from option_parser import OptionParser


class AutomatedNetworkPropagationClientOptionParser(OptionParser):
    class Namespace:
        config_path: str
        log_path: str

    def __init__(self, *args, **kwargs):
        super().__init__(
            *args,
            **(
                dict(description='Run a client that obtains lists of IP addresses and networks.') | kwargs
            )
        )
        self.add_argument(
            '--config-path',
            default='automated_network_propagation_client.toml',
            help='The path where to store logs.'
        )

        self.add_argument(
            '--log-path',
            default='automated_network_propagation_client.log',
            help='The path where to store logs.'
        )
