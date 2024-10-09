from time import time
import six
import json
import sys
from chameleon import PageTemplate


BIGTABLE_ZPT = """\
<table xmlns="http://www.w3.org/1999/xhtml"
xmlns:tal="http://xml.zope.org/namespaces/tal">
<tr tal:repeat="row python: options['table']">
<td tal:repeat="c python: row.values()">
<span tal:define="d python: c + 1"
tal:attributes="class python: 'column-' + %s(d)"
tal:content="python: d" />
</td>
</tr>
</table>""" % six.text_type.__name__


def function_handler(request_json):
    num_of_rows = request_json['num_of_rows']
    num_of_cols = request_json['num_of_cols']

    start = time()
    tmpl = PageTemplate(BIGTABLE_ZPT)

    data = {}
    for i in range(num_of_cols):
        data[str(i)] = i

    table = [data for x in range(num_of_rows)]
    options = {'table': table}

    data = tmpl.render(options=options)
    latency = time() - start

    return "latency : " + str(latency)


def main():
    if len(sys.argv) != 2:
        print("usage: python3 main.py <json_string>")
        return
    json_string = sys.argv[1]
    json_req = json.loads(json_string)
    function_handler(json_req)


if __name__ == "__main__":
    main()
