# -*- coding: utf-8 -*-

"""The base Controller API."""

from tg import TGController, tmpl_context as c
from tg.render import render
from tg import request
from tg.i18n import ugettext as _, ungettext
import sauce.model as model

__all__ = ['BaseController']


class BaseController(TGController):
    """
    Base class for the controllers in the application.

    Your web application should have one of these. The root of
    your application is used to compute URLs used by your app.

    """

    def __call__(self, environ, start_response):
        """Invoke the Controller"""
        # TGController.__call__ dispatches to the Controller method
        # the request is routed to. This routing information is
        # available in environ['pylons.routes_dict']

        request.identity = request.environ.get('repoze.who.identity')
        c.identity = request.identity
        try:
            request.user = request.identity.get('user')
        except:
            request.user = None
        finally:
            request.student = None
            request.teacher = None
            if type(request.user) == model.Student:
                request.student = request.user
            elif type(request.user) == model.Teacher:
                request.teacher = request.user
            c.student = request.student
            c.user = request.user
            c.student = request.student
            c.teacher = request.teacher
        
        return TGController.__call__(self, environ, start_response)

