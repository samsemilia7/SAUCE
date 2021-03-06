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

<%inherit file="local:templates.master"/>

<%def name="title()">
  System for AUtomated Code Evaluation
</%def>

<div class="page-header">
  <h1>SAUCE <small>System for AUtomated Code Evaluation</small></h1>
</div>

<div class="row">
  <div class="span8">
    <div class="hero-unit">
      <p>
        <strong>SAUCE</strong> is a language-independent, web-based automated
        assessment tool for programming assignments in practical programming courses
        within academic environments like universities and schools.
      </p>
      <p><a class="pull-right btn btn-primary btn-large" href="${tg.url('/about')}">Learn more &raquo;</a></p>
    </div>
  </div>

  <div class="span3 offset1">
    <div class="pull-right"><img height=248 width=248 src="${tg.url('/images/sauce_logo_big.png')}" /></div>
    <div class="pull-right"><em><small>Image by <a href="http://www.abstractnonsense.de">Christian Hundt</a></small></em></div>
  </div>
</div>
