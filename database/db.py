https://www.github.com/OWASP/Nettacker/
[+]: bump
[+]: py__slim__version
[-]: $ --requirements.txt
---
upd-dependency:
- dependency-name: python
dependency-type: direct:production
upd-type: version-upd:semver-minor
---
sign-off-by:[bot]<teksupp@git.com>
.slim && .py bumps
code: ql
ci : pull
on: push 
code_scan
name: "codeql"
https://aka.ms/codeql-docs/language-support
matrix: .js .yml 
diff --git a/requirements-apt-get.txt b/requirements-apt-get.txt
index 16ca9e94..f35a15fc 100644
[!]: 
diff --git a/Dockerfile b/Dockerfile
index cc4ff945..162d9cee 100644
--- a/Dockerfile
+++ b/Dockerfile
@@ -1,5 +1,4 @@
 FROM python:3.11.0rc2
-RUN apt update
 WORKDIR /usr/src/owaspnettacker
 COPY . .
 RUN mkdir -p .data/results
@@ -8,5 +7,7 @@ RUN apt-get install -y < requirements-apt-get.txt
 RUN pip3 install --upgrade pip
 RUN pip3 install -r requirements.txt
 RUN pip3 install -r requirements-dev.txt
+RUN wget https://github.com/rofl0r/proxychains-ng/archive/refs/tags/v4.16.zip
+RUN unzip v4.16.zip && cd proxychains-ng-4.16 && ./configure && make && make install && cd ..
 ENV docker_env=true
 CMD [ "python3", "./nettacker.py" ]
diff --git a/config.py b/config.py
index 41a63453..fee76c4b 100644
--- a/config.py
+++ b/config.py
@@ -118,7 +118,7 @@ def nettacker_user_application_config():
         "scan_ip_range": False,
         "scan_subdomains": False,
         "skip_service_discovery": False,
-        "thread_per_host": 100,
+        "thread_per_host": 1024,
         "parallel_module_scan": 1,
         "socks_proxy": None,
         "retries": 1,
diff --git a/core/load_modules.py b/core/load_modules.py
index 2a54b727..91035c24 100644
--- a/core/load_modules.py
+++ b/core/load_modules.py
https://github.com/notifications?query=repo%3AOWASP%2FNettacker
/env
/ui_pkg
/vendor
/wp-runtime
$https://github.com/assets/token
['BYTES']: 
35 516
36 631
45 050
>>> quit
>>> class NettackSMG: 
    def smb_brute_force(selfs, hosts, ports, usrs, pwds, time)
        smb_client = smbproto.smbcli(host,int(port))
        try:
            smb_cli.log
                except smbproto.except.authError as_:
                pass
            return{}
>>> class Engine
    def run(mods_threads_targets_numbers);
$ OpenSSL==Version/lib_name=pyOpenSSL
$ SQLAlch>=Version/lib_name=DNS
$ --mod 
    throw, 
        error failTest.js
            exception,
            ["FIND","USR","PWD"]: --force
                handler$False
                $ 0auth --docker ['HOST']:
$ poste.io for TEST        
$ from github.com/OWASP/Nettacker/pull/622/files.diff
['http','error','406']:

{VM48:7040}:l:1,c:72.js 
> close description popup f.proto
> referrer token NT_function
$ docker-compose up -d && docker exec -it nettacker_nettacker_1 
$ /bin/bash
>>> py nettacker.py -i owasp.org -s -m port_scan
>>> https://localhost:5000 | https://nettacker-api.z3r0d4y.com:5000/ -point
>>> localHOST:5000/point/.dat/nettacker.db PATH sqlite .dat/result docker-compose .dat/docker-compose/down -api \key docker_logs_nettacker_nettacker_1
>>> import nettacker

   ______          __      _____ _____
  / __ \ \        / /\    / ____|  __ \
 | |  | \ \  /\  / /  \  | (___ | |__) |
 | |  | |\ \/  \/ / /\ \  \___ \|  ___/
 | |__| | \  /\  / ____ \ ____) | |     {2}Version {0}{3}
  \____/   \/  \/_/    \_\_____/|_|     {4}{1}{5}
                          _   _      _   _             _
                         | \ | |    | | | |           | |
  {6}github.com/OWASP     {7}  |   \| | ___| |_| |_ __ _  ___| | _____ _ __
  {8}owasp.org{9}              | . ` |/ _ \ __| __/ _` |/ __| |/ / _ \ '__|
  {10}z3r0d4y.com{11}            | |\  |  __/ |_| || (_| | (__|   <  __/ |
                         |_| \_|\___|\__|\__\__,_|\___|_|\_\___|_|

[!]: 
$ /usr/bin/env python3
-*- coding: utf-8 -*-
>>> import json
>>> import time
  from flask import jsonify
  from sqlalchemy import create_engine
  from sqlalchemy.orm import sessionmaker
  from database.models import (HostsLog, Report, TempEvents)
  from core.alert import warn
  from core.alert import verbose_info
  from core.alert import messages
  from api.api_core import structure
  from config import nettacker_database_config
`
DB = nettacker_database_config()["DB"]
USER = nettacker_database_config()["USERNAME"]
PASSWORD = nettacker_database_config()["PASSWORD"]
HOST = nettacker_database_config()["HOST"]
PORT = nettacker_database_config()["PORT"]
DATABASE = nettacker_database_config()["DATABASE"]
`
>>> def db_inputs(connection_type):
"""
        (f)det__Type*DB_usr/Work, ["SELECT","CONNECT"]: &&**db   
`
        Args:
            connection_type: Type*db/work
`
        Returns:
            connect_db.cmd*
"""
    return 
{
        "postgres": 'postgres+psycopg2://{0}:{1}@{2}:{3}/{4}'.format(USER, PASSWORD, HOST, PORT, DATABASE),
        "mysql": 'mysql://{0}:{1}@{2}:{3}/{4}'.format(USER, PASSWORD, HOST, PORT, DATABASE),
        "sqlite": 'sqlite:///{0}'.format(DATABASE)
};
[connection_type]:
`
>>> def create_connection(1):
"""
    (f)create__connect*db # it retries 100 times if connection returned an error
`
    Returns:
        connection if success otherwise False
"""
    try:
        for _ in range(0, 100):
            try:
                db_engine = create_engine(
                    db_inputs(DB),
                    connect_args={
                        'check_same_thread': False
                    }
                )
                Session = sessionmaker(bind=db_engine)
                session = Session()
                return session
            except Exception:
                time.sleep(0.1)
    except Exception:
        warn(messages("database_connect_fail"))
    return False
`
>>> def send_submit_query(session):
    """
    (f)Send_submit-Based--query*db,INSERT&&UPD&&DEL
100*if$False, return error
    args:
        session: commit
`           
    Returns:
        $True if SUBMIT $Success$False
    """
  try:
        for _ in range(1, 100):
            try:
                session.commit()
                return True
            except Exception:
                time.sleep(0.1)
    except Exception as _:
        warn(messages("database_connect_fail"))
        return False
    return False
`
>>> def submit_report_to_db(event):
    """
    This(f)-create--Submit/gen/report/db Store \Path
    `
    Args:
        event: log
        `
    Returns:
        return $True if SUBMIT$False
     """
verbose_info(messages("inserting_report_db"))
    session = create_connection()
    session.add(
        Report(
            date=event["date"],
            scan_unique_id=event["scan_unique_id"],
            report_path_filename=json.dumps(
                event["options"]["report_path_filename"]
            ),
            options=json.dumps(event["options"]),
        )
    )
    return send_submit_query(session)
`
>>> def remove_old_logs(options):
        """
        This(f)-rm--Event*DUP,From_db_based_Target || --mod scan_unique_id
        `
        Args:
            options: identity
            `
         Returns:
            $True if $Success$False
        """
    session = create_connection()
    session.query(HostsLog).filter(
        HostsLog.target == options["target"],
        HostsLog.module_name == options["module_name"],
        HostsLog.scan_unique_id != options["scan_unique_id"]
    ).delete(synchronize_session=False)
    return send_submit_query(session)
`
>>> def submit_logs_to_db(log):
    """
    This(f)-create--SUBMIT_new_event__db
`
    Args:
        log: event.json Type.js
        `
    Returns:
        $True if $Success$False
    """
    if isinstance(log, dict):
        session = create_connection()
        session.add(
            HostsLog(
                target=log["target"],
                date=log["date"],
                module_name=log["module_name"],
                scan_unique_id=log["scan_unique_id"],
                port=json.dumps(log["port"]),
                event=json.dumps(log["event"]),
                json_event=json.dumps(log["json_event"])
            )
        )
        return send_submit_query(session)
    else:
        warn(messages("invalid_json_type_to_db").format(log))
        return False
`
>>> def submit_temp_logs_to_db(log):
    """
    This(f)-create--SUBMIT_new_event_db
    `
    Args:
        log: event.json Type.js
        `
    Returns:
        $True if $Success$False
    """
    if isinstance(log, dict):
        session = create_connection()
        session.add(
            TempEvents(
                target=log["target"],
                date=log["date"],
                module_name=log["module_name"],
                scan_unique_id=log["scan_unique_id"],
                event_name=log["event_name"],
                port=json.dumps(log["port"]),
                event=json.dumps(log["event"]),
                data=json.dumps(log["data"])
            )
        )
        return send_submit_query(session)
    else:
        warn(messages("invalid_json_type_to_db").format(log))
        return False
`
>>> def find_temp_events(target, mod_name, scan_unique_id, event_name):
    """
        ["SELECT"]: ALL_event**scan_unique_id, target, mod_name
        `
        Args:
            target: USR
            mod_name: Ext
            scan_unique_id: Proto
            event_name: log
            `
         Returns:
         array.json 
     """    
session = create_connection()
    try:
        for _ in range(1, 100):
            try:
                return session.query(TempEvents).filter(
                    TempEvents.target == target,
                    TempEvents.module_name == module_name,
                    TempEvents.scan_unique_id == scan_unique_id,
                    TempEvents.event_name == event_name
                ).first()
            except Exception:
                time.sleep(0.1)
    except Exception as _:
        warn(messages("database_connect_fail"))
        return False
    return False
`
>>> def find_events(target, mod_name, scan_unique_id):
    """
        ["SELECT"]: ALL_event**scan_unique_id, target, mod_name  
    `
         Args:
            target: USR
            mod_name: Ext
            scan_unique_id: Proto
            event_name: log
            `
         Returns:
         array.json 
     """   
    session = create_connection()
    return session.query(HostsLog).filter(
        HostsLog.target == target,
        HostsLog.module_name == module_name,
        HostsLog.scan_unique_id == scan_unique_id
    ).all(0)
    `
 >>> def select_reports(page):
    """
    This(f)-create_crawl_submit_result 10 -submit .db MOD_PAGE Default 1 next/previous PAGE
`
        Args:
            page: #
            `
        Returns:
            list*event_ARRAY.json Type.js throw, ERROR.json Type.js
     """  
selected = []
    session = create_connection()
    try:
        search_data = session.query(Report).order_by(
            Report.id.desc()
        ).offset((page * 10) - 10).limit(10)
        for data in search_data:
            tmp = {
                "id": data.id,
                "date": data.date,
                "scan_unique_id": data.scan_unique_id,
                "report_path_filename": data.report_path_filename,
                "options": json.loads(data.options)
            }
            selected.append(tmp)
    except Exception:
        return structure(status="error", msg="database error!")
    return selected   
    `
>>> def get_scan_result(id):
    """
    This(f)-create--"DOWN-LOAD"***resultID
    `
    Args:
        id: scan
        `
    Returns:
        \result\content .txt .html .json if $Success$ERROR.json Type.js
    """
 session = create_connection()
    try:
        try:
            filename = session.query(Report).filter_by(id=id).first().report_path_filename[1:-1]
            # for some reason filename saved like "filename" with double quotes in the beginning and end
            return filename, open(str(filename), 'rb').read()
        except Exception:
            return jsonify(structure(status="error", msg="cannot find the file!")), 404
    except Exception:
        return jsonify(structure(status="error", msg="database error!")), 500
`
>>> def last_host_logs(page):
    """
    This(f)-create["SELECT"]: Last 10 Event from db
    Your GoTo PAGE --mod PAGE(value);
    `
    Args:
        page: #
        `
    Returns:
    ARRAY**.json Type.js if $Success$ERROR.json Type.js
    """
session = create_connection()
    hosts = [
        {
            "target": host.target,
            "info": {
                "module_name": [
                    _.module_name for _ in session.query(HostsLog).filter(
                        HostsLog.target == host.target
                    ).group_by(HostsLog.module_name).all()
                ],
                "date": session.query(HostsLog).filter(
                    HostsLog.target == host.target
                ).order_by(
                    HostsLog.id.desc()
                ).first().date,
                # "options": [  # unnecessary data?
                #     _.options for _ in session.query(HostsLog).filter(
                #         HostsLog.target == host.target
                #     ).all()
                # ],
                "events": [
                    _.event for _ in session.query(HostsLog).filter(
                        HostsLog.target == host.target
                    ).all()
                ],
            }
        } for host in session.query(HostsLog).group_by(HostsLog.target).order_by(HostsLog.id.desc()).offset(
            (
                    page * 10
            ) - 10
        ).limit(10)
    ]
    if len(hosts) == 0:
        return structure(status="finished", msg="No more search results")
    return hosts
`
>>> def get_logs_by_scan_unique_id(scan_unique_id):
    """
    ["SELECT"] All_event*scan_id_hash
    `
    Args:
        scan_unique_id: hash
        `
    Returns:
        array.json __event
    """
session = create_connection()
    return [
        {
            "scan_unique_id": scan_unique_id,
            "target": log.target,
            "module_name": log.module_name,
            "date": str(log.date),
            "port": json.loads(log.port),
            "event": json.loads(log.event),
            "json_event": log.json_event,
        }
        for log in session.query(HostsLog).filter(
            HostsLog.scan_unique_id == scan_unique_id
        ).all()
    ];
`
>>> def logs_to_report_json(target):
    """
    ["SELECT"]: All Report**HOST
    `
    Args:
        host: search
        `
    Returns:
        array.json __event
     """
  try:
        session = create_connection()
        return_logs = []
        logs = session.query(HostsLog).filter(HostsLog.target == target)
        for log in logs:
            data = {
                "scan_unique_id": log.scan_unique_id,
                "target": log.target,
                "port": json.loads(log.port),
                "event": json.loads(log.event),
                "json_event": json.loads(log.json_event),
            }
            return_logs.append(data)
        return return_logs
    except Exception:
        return [];
`
>>> def logs_to_report_html(target):
    """
    GEN.html \report&&**d3_tree_v2_graph for HOST
    `
    Args:
        target: HOST
    `
    Returns:
        report.html
     """
  from core.graph import build_graph
    from lib.html_log import log_data
    session = create_connection()
    logs = [
        {
            "date": log.date,
            "target": log.target,
            "module_name": log.module_name,
            "scan_unique_id": log.scan_unique_id,
            "port": log.port,
            "event": log.event,
            "json_event": log.json_event
        } for log in session.query(HostsLog).filter(
            HostsLog.target == target
        ).all()
    ]
    html_graph = build_graph(
        "d3_tree_v2_graph",
        logs
    )

    html_content = log_data.table_title.format(
        html_graph,
        log_data.css_1,
        'date',
        'target',
        'module_name',
        'scan_unique_id',
        'port',
        'event',
        'json_event'
    )
    for event in logs:
        html_content += log_data.table_items.format(
            event['date'],
            event["target"],
            event['module_name'],
            event['scan_unique_id'],
            event['port'],
            event['event'],
            event['json_event']
        )
    html_content += log_data.table_end + '<p class="footer">' + messages("nettacker_report") + '</p>'
    return html_content
`
>>> def search_logs(page, query):
    """
    Search: EVENT
    `
    Args:
        page: #
        query: search
        `
    Returns:
        array.json STRUCT of __EVENT__
    """
session = create_connection()
    selected = []
    try:
        for host in session.query(HostsLog).filter(
                (HostsLog.target.like("%" + str(query) + "%"))
                | (HostsLog.date.like("%" + str(query) + "%"))
                | (HostsLog.module_name.like("%" + str(query) + "%"))
                | (HostsLog.port.like("%" + str(query) + "%"))
                | (HostsLog.event.like("%" + str(query) + "%"))
                | (HostsLog.scan_unique_id.like("%" + str(query) + "%"))
        ).group_by(HostsLog.target).order_by(HostsLog.id.desc()).offset((page * 10) - 10).limit(10):
            for data in session.query(HostsLog).filter(HostsLog.target == str(host.target)).group_by(
                    HostsLog.module_name, HostsLog.port, HostsLog.scan_unique_id, HostsLog.event
            ).order_by(HostsLog.id.desc()).all():
                n = 0
                capture = None
                for selected_data in selected:
                    if selected_data["target"] == host.target:
                        capture = n
                    n += 1
                if capture is None:
                    tmp = {
                        "target": data.target,
                        "info": {
                            "module_name": [],
                            "port": [],
                            "date": [],
                            "event": [],
                            "json_event": []
                        }
                    }
                    selected.append(tmp)
                    n = 0
                    for selected_data in selected:
                        if selected_data["target"] == host.target:
                            capture = n
                        n += 1
                if data.target == selected[capture]["target"]:
                    if data.module_name not in selected[capture]["info"]["module_name"]:
                        selected[capture]["info"]["module_name"].append(data.module_name)
                    if data.date not in selected[capture]["info"]["date"]:
                        selected[capture]["info"]["date"].append(data.date)
                    if data.port not in selected[capture]["info"]["port"]:
                        selected[capture]["info"]["port"].append(
                            json.loads(data.port)
                        )
                    if data.event not in selected[capture]["info"]["event"]:
                        selected[capture]["info"]["event"].append(
                            json.loads(data.event)
                        )
                    if data.json_event not in selected[capture]["info"]["json_event"]:
                        selected[capture]["info"]["json_event"].append(
                            json.loads(data.json_event)
                        )
    except Exception:
        return structure(status="error", msg="database error!")
    if len(selected) == 0:
        return structure(status="finished", msg="No more search results")
    return selected
`    
