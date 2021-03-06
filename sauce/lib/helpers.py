# -*- coding: utf-8 -*-

"""WebHelpers used in SAUCE.

@author: moschlar
"""
#
## SAUCE - System for AUtomated Code Evaluation
## Copyright (C) 2013 Moritz Schlarb
##
## This program is free software: you can redistribute it and/or modify
## it under the terms of the GNU Affero General Public License as published by
## the Free Software Foundation, either version 3 of the License, or
## any later version.
##
## This program is distributed in the hope that it will be useful,
## but WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
## GNU Affero General Public License for more details.
##
## You should have received a copy of the GNU Affero General Public License
## along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

from datetime import datetime

from tg import config, request, url as tgurl

from webhelpers import date, feedgenerator, html, number, misc, text
from webhelpers.html.tags import link_to, link_to_unless
from webhelpers.html.tools import mail_to
from webhelpers.text import truncate
from webhelpers.date import distance_of_time_in_words

import re

from pygments import highlight as _highlight
from pygments.lexers import get_lexer_by_name
from pygments.formatters.html import HtmlFormatter
from difflib import unified_diff

#log = logging.getLogger(__name__)

cut = lambda text, max = 200: truncate(text, max, whole_word=True)
strftimedelta = lambda delta, granularity='minute': distance_of_time_in_words(datetime.now(), datetime.now() + delta, granularity)

#----------------------------------------------------------------------


def link(label, url='', **attrs):
    return link_to(label, tgurl(url), **attrs)


def striphtml(text):
    return re.sub('<[^<]+?>', ' ', text).strip() if text else u''


def current_year():
    now = datetime.now()
    return now.strftime('%Y')


def icon(icon_name, white=False):
    if (white):
        return html.literal('<i class="icon-%s icon-white"></i>' % icon_name)
    else:
        return html.literal('<i class="icon-%s"></i>' % icon_name)

#----------------------------------------------------------------------


class MyHtmlFormatter(HtmlFormatter):
    '''Create lines that have unique name tags to allow highlighting

    Each line has an anchor named <lineanchors>-<linenumber>
    '''

    def _wrap_lineanchors(self, inner):
        s = self.lineanchors
        i = 0
        for t, line in inner:
            if t:
                i += 1
                yield 1, u'<a name="%s-%d"></a><span class="%s-%d">%s</span>' % (s, i, s, i, line)
            else:
                yield 0, line

formatter = MyHtmlFormatter(style='default', linenos=True, lineanchors='line')
style = formatter.get_style_defs()


def udiff(a, b, a_name=None, b_name=None, **kw):
    '''Automatically perform splitlines on a and b before diffing and join output'''
    if not a:
        a = u''
    if not b:
        b = u''
    return '\n'.join(unified_diff(a.splitlines(), b.splitlines(),
        a_name, b_name, lineterm='', **kw))


def highlight(code, lexer_name='text'):
    #formatter = MyHtmlFormatter(style='default', linenos=True, lineanchors='line')
    if code:
        return _highlight(code, get_lexer_by_name(lexer_name), formatter)
    else:
        return u''


def make_login_url():
    url = '/login'
    params = {'came_from': request.environ['PATH_INFO']}
    qualified = False
    try:
        url = config.login.url
        qualified = config.login.qualified
        if config.login.referrer_key:
            params = {config.login.referrer_key: tgurl(request.environ['PATH_INFO'], qualified=qualified)}
    except:
        pass
    return tgurl(url, params)


def make_logout_url():
    url = '/logout_handler'
    params = {}
    qualified = False
    try:
        url = config.logout.url
        qualified = config.logout.qualified
        if config.logout.referrer_key:
            params = {config.logout.referrer_key: tgurl(request.environ['PATH_INFO'], qualified=qualified)}
    except:
        pass
    return tgurl(url, params=params)
