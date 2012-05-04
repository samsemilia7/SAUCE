<%inherit file="local:templates.master"/>

<%def name="title()">
  Submissions
</%def>

<h2>Submissions</h2>

% if hasattr(c, 'table'):
    <div class="crud_table">
     ${tmpl_context.table(value=value_list, attrs=dict(style="height:200px; border:solid black 3px;")) |n}
    </div>
% else:
<table>
  <tr>
    <th>ID</th>
    <th>Assignment</th>
    <th>Language</th>
    <th>Result</th>
    <th>Created</th>
    <th>Modified</th>
    <th>Runtime</th>
  </tr>
    %for submission in submissions:
    <tr>
        <th>${submission.link}</th>
        <td>${submission.assignment.link}</td>
        <td>${submission.language.name}</td>
        % if not submission.complete:
          <td>n/a</td>
        % else:
          <td>
          % if submission.result:
            <span class="green">ok</span>
          % else:
            <span class="red">fail</span>
          </td>
          % endif
         <td>${submission.created.strftime('%x %X')}</td>
         <td>${submission.modified.strftime('%x %X')}</td>
         <td>${'%.3f sec' % submission.runtime}</td>
## TODO: Judgement Link
        % endif
        
    </tr>
    %endfor
</table>
  
##% if submissions.pager:
##  <p>${submissions.pager('Pages: $link_previous ~2~ $link_next')}</p>
##% endif

% endif
