# !/usr/bin/env python3
# -*- coding: utf-8 -*-
# Author: Mr.Bingo

import os
import time
import argparse
import xml.etree.ElementTree as ET
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, Sequence, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker

BaseModle = declarative_base()

class Output(BaseModle):
    def __init__(self, portinfo):
        pass  # 可能需要处理格式文件

        for a, b in portinfo.items():
            setattr(self, a, b if isinstance(b, (int, str)) else None)

    __tablename__ = "nmap2db"
    id = Column(Integer, primary_key=True, autoincrement=True)
    scantime = Column(DateTime)
    protocol = Column(String(10))
    ip = Column(String(30))
    port = Column(Integer)
    ipport = Column(String(30))
    name = Column(String(30))
    product = Column(String(100))
    mark = Column(String(50))

    def __repr__(self):
        return "%s\t%s\t%s" \
               % (self.ip, str(self.port), self.mark)

    def to_dict(self):
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}


def getDBurl(dbtype,username,password,host,port,db):
    dbtypedict = {  "postgresql":["postgresql", 5432],
                    "mysql":["mysql", 3306],
                    "oracle":["oracle", 1521],
                    "mssql":["mssql", 1433],
                    "sqlite":["sqlite", ""],
                    "csv":["csv", ""]
                  }

    # 链接数据库   '数据库类型+数据库驱动名称://用户名:口令@机器地址:端口号/数据库名'
    if dbtype not in ('sqlite','csv'):
        dburl = "%s://%s:%s@%s:%d/%s"%(dbtypedict[dbtype][0],username,password,host, int(port) if port is not None else dbtypedict[dbtype][1],db)
    else:
        dburl = "%s:///%s" % (dbtypedict[dbtype][0], os.path.realpath(db+"."+dbtype))
    return dburl

def conv2db(xml,DBurl):
    print("[Parsing xml]")
    jsoninfo = []
    tree = ET.parse(xml)
    root = tree.getroot()
    for host in root.findall("host"):
        portinfo = {}
        recordflag = 0
        portinfo["scantime"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(int(host.attrib["starttime"])))
        if host.find("address").attrib["addrtype"] in ("ipv4","ipv6"):
            portinfo["ip"] = host.find("address").attrib["addr"]

        for port in host.findall("./ports/port"):
            state = port.find("state")
            service = port.find("service")
            if state.attrib["state"].lower() == "open":
                portinfo["protocol"]    =   port.get("protocol","")
                portinfo["port"]        =   port.get("portid","")
                portinfo["name"]        =   service.get("name","")
                portinfo["product"]     =   service.get("product","")
                portinfo["ipport"]      =   portinfo["ip"]+":"+portinfo["port"]
                if portinfo["name"].lower() in ("http",'http-alt'):
                    portinfo["mark"] = "http://%s:%s"%(portinfo["ip"],portinfo["port"])
                elif portinfo["name"].lower() in ("https",'https-alt'):
                    portinfo["mark"] = "https://%s:%s"%(portinfo["ip"],portinfo["port"])
                else:
                    portinfo["mark"] = ""
                jsoninfo.append(portinfo.copy())
                recordflag = 1
        if recordflag == 0:
            portinfo["protocol"]    =   ""
            portinfo["port"]        =   ""
            portinfo["name"]        =   ""
            portinfo["product"]     =   ""
            portinfo["mark"]        =   ""
            jsoninfo.append(portinfo)

    # print(listinfo)
    if DBurl.split("://")[0] == "csv":
        with open(DBurl.split(":///")[1],"a+", encoding='utf-8') as f:
            for item in jsoninfo:
                strline =   item["scantime"]+","\
                            + item["ip"]+"," \
                            + item["protocol"] + "," \
                            + item["port"] + ","\
                            + item["name"]+"," \
                            + item["product"] + "," \
                            + item["mark"] + ",\n"
                f.write(strline)
    else:
        DBsession = None
        try:
            # 链接数据库   '数据库类型+数据库驱动名称://用户名:口令@机器地址:端口号/数据库名'
            DBengine = create_engine(DBurl, echo=False)  # echo - logging标志

            # Create a Schema
            BaseModle.metadata.create_all(DBengine)

            # Create a DBsession
            DBsession = sessionmaker(bind=DBengine)

        except Exception as e:
            print( "[error] something occurred while create the database\n\t%s"%e)

        print("[Processing]")
        dbsession = DBsession()
        itemlist = []
        counter = 0
        for item in jsoninfo:
            counter += 1
            itemlist.append(Output(item))
            if counter % 100 == 0 or counter == len(jsoninfo):
                dbsession.add_all(itemlist)
                itemlist = []
                print(" \b\b" * 100, end="")
                print("."*int(counter * 50 / len(jsoninfo))+" ( "+str(counter*100/len(jsoninfo))[:5]+"% ) ", end="", flush=True)
                dbsession.commit()
        dbsession.close()

def main():
    headCharPic = "\r        .--.\n" \
                  "       |o_o |    ------------------ \n" \
                  "       |:_/ |   <      Mr.Bingo     >\n" \
                  "      //   \ \   ------------------ \n" \
                  "     (|     | ) < https://oddboy.cn >\n" \
                  "    /'\_   _/`\  ------------------ \n" \
                  "    \___)=(___/\n"\
                  " nmap2db: convert namp output(XML) to Databases.\n"
    print(headCharPic)
    # Creating a parser
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', dest="xml", required=True, help='Nmap output xml file, you can get it by : nmap 192.168.0.1/24 -oX output.xml')
    parser.add_argument('-t', required=True, dest='dbtype', choices=["postgresql", "mysql", "oracle", "mssql", "sqlite", "csv"], help='Database Type, eg: PostgreSQL, MySQL, Oracle, MSSql, SQLite, CSV')
    parser.add_argument('-u', dest='username', help='DB username')
    parser.add_argument('-p', dest='password', help='DB password')
    parser.add_argument('-H', dest='host', help='DB host')
    parser.add_argument('-P', dest='port', help='DB port')
    parser.add_argument('-o', default="output", dest='db', help='DB Schema or DB file path')
    # parser.add_argument('-T', dest="tablename", default="nmap2db", help="As table name when store in DBs")

    args = parser.parse_args()

    if not os.path.exists(args.xml):
        print('the xml file ( %s ) is not exist!' % args.xml)
        return

    if args.dbtype.lower() in ('postgresql','mysql','oracle','mssql'):
        if args.username is None or args.password is None or args.host is None:
            print("please specify arguments: username(-u), password(-p), host(-H), [port(-P)]")
            return

    DBurl = getDBurl(args.dbtype,args.username,args.password,args.host,args.port,args.db)
    # print(DBurl)
    conv2db(args.xml.lower(), DBurl)

    print("\n"+"*"*20+"\n\tDone!\n"+"*"*20)

if __name__ == "__main__":
    main()
