# -*- coding: utf-8 -*-
import requests
from bs4 import BeautifulSoup
import os
import urllib2
import re
import json
import shutil


class chrome_cve:
    #define some varible
    def __init__(self):
        #set request header 
        self.user_agent = 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36'
        self.headers = {'User-Agent': self.user_agent}
        #set request proxy
        self.proxy_handler = urllib2.ProxyHandler( {"http":"web-proxyhk.oa.com:8080", "https":"web-proxyhk.oa.com:8080"} )
        self.opener = urllib2.build_opener(self.proxy_handler)
	urllib2.install_opener(self.opener)
        #initial list to store archive pags
	#fp = open('db.json','r')
        #self.cve_db = json.loads(fp.read())
	#fp.close()
	self.archive_list = [];

    #get archive pages from 'googlechromereleases.blogspot.com'
    def get_archive_pages(self):
        try:
            target_url='https://googlechromereleases.blogspot.com/'
            #urllib2.install_opener(self.opener)
            response = urllib2.urlopen(target_url)
            page_data = response.read()
            soup = BeautifulSoup(page_data,'html.parser')
            for archive in soup.find_all('a',href=re.compile('googlechromereleases.blogspot.com.*archive.html')):
                self.archive_list.insert(0,archive.get('href'))
        except urllib2.URLError,e:
            print "something wrong\n"

    #get issue pages from 'googlechromereleases.blogspot.com'
    def get_issue_pages(self,Url):
        try:
            #urllib2.install_opener(self.opener)
            response = urllib2.urlopen(Url)
            page_data = response.read()
            soup = BeautifulSoup(page_data,'html.parser')
            for link in soup.find_all('a',href=re.compile(r'(?u)https?://code.google.com/p/chromium/issues/detail.id.\d{6}|https?://crbug.com/\d{6}')):
		thirdpartid = re.search('\d{6}',link.get('href')).group(0)
		#for record in self.cve_db:
		#    if record.get('thirdpartyid') == thirdpartid:
		#	cve_id = record.get('cve')
		#	title = record.get('title')
                self.get_cve_data(link.get('href'))
        except urllib2.URLError,e:
            print "something wrong at get issue pages %s\n"%Url

    #get cve poc
    def get_cve_data(self,Url):
        try:
            response = urllib2.urlopen(Url)
            page_data = response.read()
            soup = BeautifulSoup(page_data,'html.parser')
            cve_id = ''
            disc = ''
            if soup.find('title',text=re.compile('You do not have permission|Sign in',re.I)):
                print 'do not have permission to view'
                return
            for record in soup.find_all('a',href=re.compile(r'(?u)list.q=label.CVE-\d{4}-\d{4}')):
                cve_id = record.get('title')
	    if cve_id != '':
                print cve_id
                disc = soup.title.text.replace('/','_').replace('\n','_')
                dir_path = './Sample/%s__%s'%(cve_id,disc)
		print dir_path
                if os.path.isdir(dir_path):
                    print 'already have'
                    return 
                os.mkdir(dir_path)
                for link in soup.find_all('a',href=re.compile(r'(?u)attachment.aid=\d{4,8}'),text='Download'):
                    print link.parent.parent.b.text, '       extension-----',link.parent.parent.b.text.split('.')[-1]
                    file_url = 'https://bugs.chromium.org/p/chromium/issues/%s'%link.get('href')
                    file_name = dir_path+'/'+link.parent.parent.b.text
                    self.get_poc(file_url,file_name)
        except urllib2.URLError,e:
            print "something wrong at get cve data %s\n"%Url
    
    #get attachment
    def get_poc(self,Url,path):
    	fp = open(path,'wb')
	resp = urllib2.urlopen(Url)
	fp.write(resp.read())
	fp.close()
	 
    
    def start(self):
        print 'start'
        self.get_archive_pages()
        for link in self.archive_list:
            if int(re.search(r'(?u)\d{4}',link).group()) >= 2014:
                self.get_issue_pages(link)

spider = chrome_cve()
spider.start();
