# -*- coding: utf_8 -*-
"""List all java files."""

import re
import shutil
import os

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.conf import settings
from django.utils.html import escape

from MobSF.utils import (
    PrintException
)


def __for_file(src, dir_name, jfile, request, html):
    """Add to html for every file."""
    file_path = os.path.join(src, dir_name, jfile)
    if "+" in jfile:
        fp2 = os.path.join(src, dir_name, jfile.replace("+", "x"))
        shutil.move(file_path, fp2)
        file_path = fp2
    fileparam = file_path.replace(src, '')
    if any(cls in fileparam for cls in settings.SKIP_CLASSES) is False:
        html += (
            "<tr><td><a href='../ViewSource/?file=" + escape(fileparam) +
            "&md5=" + request.GET['md5'] +
            "&type=" + request.GET['type'] + "'>" +
            escape(fileparam) + "</a></td></tr>"
        )
    return html


def run(request):
    """Show the java code."""
    try:
        if re.match('^[0-9a-f]{32}$', request.GET['md5']):
            if request.GET['type'] == 'eclipse':
                src = os.path.join(settings.UPLD_DIR, request.GET['md5'] + '/src/')
            elif request.GET['type'] == 'studio':
                src = os.path.join(settings.UPLD_DIR, request.GET['md5'] + '/app/src/main/java/')
            elif request.GET['type'] == 'apk':
                src = os.path.join(settings.UPLD_DIR, request.GET['md5'] + '/java_source/')
            else:
                return HttpResponseRedirect('/error/')
            html = ''
            # pylint: disable=unused-variable
            # Needed by os.walk
            for dir_name, sub_dir, files in os.walk(src):
                for jfile in files:
                    if jfile.endswith(".java"):
                        html += __for_file(src, dir_name, jfile, request, html)
        context = {
            'title': 'Java Source',
            'files': html,
            'md5': request.GET['md5'],
            'type': request.GET['type'],
        }

        template = "java.html"
        return render(request, template, context)
    except:
        PrintException("[ERROR] Getting Java Files")
        return HttpResponseRedirect('/error/')
