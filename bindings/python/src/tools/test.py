import elliptics
from elliptics.tools.stats_view import StatsView
s = elliptics.Session(elliptics.create_node(remotes=['sata01h.xxx.yandex.net:1025:10'], flags=elliptics.config_flags.no_route_list, log_level=elliptics.log_level.error))
view = StatsView(s.monitor_stat().get()[0].statistics)

print view.backends.active_threads
