<%inherit file="local:templates.master" />

<%def name="title()">
  Similarity table
</%def>

% if assignment:

<div class="page-header">
  <h1>Similarity table <small>Assignment ${assignment.id}</small></h1>
</div>

% if hasattr(c, 'backlink') and c.backlink:
  <div class="span2 pull-right">
    <a href="${c.backlink}" class="btn btn-inverse pull-right">
      <i class="icon-arrow-left icon-white"></i>&nbsp;Go back</a>
  </div>
% endif


<%def name="th(submission)">
<th class="po" rel="popover" title="Submission ${submission.id}" data-content="<dl>\
<dt>User:</dt><dd>${submission.user}</dd>\
<dt>Created:</dt><dd>${submission.created.strftime('%x %X')}</dd>\
<dt>Last modified:</dt><dd>${submission.modified.strftime('%x %X')}</dd>\
</dl>"><a href="${submission.url}">${submission.id}</a>
<span class="badge ${'' if submission.result is None else ('badge-success' if submission.result else 'badge-error')}">&nbsp;</span>
</th>
</%def>


<div class="row">
<div class="span12">
<h2>${assignment.name}</h2>

<table class="table table-condensed table-striped table-bordered">
<thead>
<tr>
<th>&nbsp;</th>
% for j, s in enumerate(submissions):
${th(s)}
% endfor
<th>&nbsp;</th>
</tr>
</thead>
<tbody>
% for i, row in enumerate(matrix):
<tr>
${th(submissions[i])}
% for j, cell in enumerate(row):
% if i == j:
  <td>&nbsp;</td>
% else:
  <td class="tt" rel="tooltip" title="${cell}">
    <a href="${tg.url('./diff/%d/%d/' % (submissions[i].id, submissions[j].id))}" style="color: ${c.rgb(cell)};">${'%.2f' % cell}</a>
  </td>
% endif
% endfor
${th(submissions[i])}
</tr>
% endfor
</tbody>
<tfoot>
<tr>
<th>&nbsp;</th>
% for j, s in enumerate(submissions):
${th(s)}
% endfor
<th>&nbsp;</th>
</tr>
</tfoot>
</table>

<script type="text/javascript">$('.po').popover({placement: 'right', delay: {show: 0, hide: 200}})</script>
<script type="text/javascript">$('.tt').tooltip({placement: 'top'})</script>

<h2>Dendrogram</h2>
<img src="${c.image}" />

</div>
</div>

%else:

% if hasattr(c, 'backlink') and c.backlink:
  <div class="span2 pull-right">
    <a href="${c.backlink}" class="btn btn-inverse">'
      <i class="icon-arrow-left icon-white"></i>&nbsp;Go back</a>
  </div>
% endif

% endif
