'''
Created on May 14, 2013

@author: moschlar
'''

from tg import config

import tw2.core as twc
import tw2.bootstrap.forms as twb
import tw2.bootstrap.wysihtml5 as twbw


__all__ = [
    'Wysihtml5',
    'MediumTextField',
    'SmallTextField',
    'CalendarDateTimePicker',
]


class LargeMixin(object):
    css_class = 'span8'


class MediumMixin(object):
    css_class = 'span4'


class SmallMixin(object):
    css_class = 'span2'


class Wysihtml5(LargeMixin, twbw.Wysihtml5):
    rows = 3
    wysihtml5_args = {
        'html': True,
    }


class MediumTextField(MediumMixin, twb.TextField):
    pass


class SmallTextField(SmallMixin, twb.TextField):
    pass


class CalendarDateTimePicker(SmallMixin, twb.CalendarDateTimePicker):
    date_format = config.D_T_FMT
    datetimepicker_args = {
        'weekStart': 1,
        'autoClose': True,
        'todayBtn': True,
        'todayHighlight': True,
        'minuteStep': 15,
    }
