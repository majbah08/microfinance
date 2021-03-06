from datetime import datetime, timedelta

import core

from project_data.models import Complain


class ChartData(object):

    @classmethod
    def get_avg_by_day(cls, user, days):
        now = datetime.now(tz=user.settings.time_zone).date()


        '''glucose_averages = project_data_complain.objects.(
            (now - timedelta(days=days)), now, user)
'''

        data = {'dates': [], 'values': []}
        for avg in glucose_averages:
            data['dates'].append(avg['record_date'].strftime('%m/%d'))
            data['values'].append(core.utils.round_value(avg['avg_value']))


        return data