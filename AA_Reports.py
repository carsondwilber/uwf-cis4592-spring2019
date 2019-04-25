import os
import AA_Constants

from AA_FileIO import *

default_scripts = []
default_styles = []
default_metas = []

class _AA_Reports_Internal:
    _audit_tag = "div"
    _audit_classes = ["audit-section"]

    _result_tag = "div"
    _result_classes = ["script-result"]
    
    _raw_tag = "div"
    _raw_classes = ["raw-output"]

    _header_tag = "div"
    _header_classes = ["audit-header"]

    _title_tag = "h3"
    _title_classes = ["audit-title"]

    _path_tag = "p"
    _path_classes = ["audit-path"]

    @staticmethod
    def _write_script(fp, src):
        fp.write('\t\t<script type="text/javascript" src="' + src + '"></script>\n')

    @staticmethod
    def _write_scripts(fp, srcs):
        for src in srcs:
            _AA_Reports_Internal._write_script(fp, src)

    @staticmethod
    def _write_style(fp, style):
        fp.write('\t\t<link rel="stylesheet" type="text/css" href="' + style + '" />\n')

    @staticmethod
    def _write_styles(fp, styles):
        for style in styles:
            _AA_Reports_Internal._write_style(fp, style)

    @staticmethod
    def _write_meta_fields(fp, fields):
        for field, value in fields:
            fp.write(field + '=' + value + ' ')

    @staticmethod
    def _write_meta(fp, meta):
        fp.write('\t\t<meta ')
        _AA_Reports_Internal._write_meta_fields(fp, meta)
        fp.write('/>')

    @staticmethod
    def _write_link(fp, link):
        fp.write('\t\t<link href="' + link + '" />\n')

    @staticmethod
    def _write_links(fp, links):
        for link in links:
            _AA_Reports_Internal._write_link(fp, link)

    @staticmethod
    def _write_dependencies(fp, **kwargs):
        for key, item in kwargs.items():
            if key == "scripts":
                _AA_Reports_Internal._write_scripts(fp, item)
            elif key == "styles":
                _AA_Reports_Internal._write_styles(fp, item)
            elif key == "meta":
                _AA_Reports_Internal._write_metas(fp, item)
            else:
                _AA_Reports_Internal._write_links(fp, item)

    @staticmethod
    def _begin_document(fp):
        fp.write('<!DOCTYPE html>\n')
        fp.write('<html>\n')

    @staticmethod
    def _write_header(fp, **kwargs):
        fp.write('\t<head>\n')
        _AA_Reports_Internal._write_dependencies(fp, **kwargs)
        fp.write('\t</head>\n')

    @staticmethod
    def _begin_body(fp):
        fp.write('\t<body>\n')

    @staticmethod
    def _end_body(fp):
        fp.write('\t</body>\n')

    @staticmethod
    def _end_document(fp):
        fp.write('</html>\n')

    @staticmethod
    def _begin_report(fp, **kwargs):
        _AA_Reports_Internal._begin_document(fp)
        _AA_Reports_Internal._write_header(fp, **kwargs)
        _AA_Reports_Internal._begin_body(fp)

    @staticmethod
    def _end_report(fp):
        _AA_Reports_Internal._end_body(fp)
        _AA_Reports_Internal._end_document(fp)

    @staticmethod
    def _begin_tag(fp, tag):
        fp.write('<' + tag + ' ')

    @staticmethod
    def _write_classes(fp, classes):
        fp.write('class="')
        for clazz in classes:
            fp.write(clazz + ' ')
        fp.write('" ')

    @staticmethod
    def _end_tag(fp):
        fp.write('/>\n')

    @staticmethod
    def _close_tag(fp, tag):
        fp.write('</' + tag + '>\n')

    @staticmethod
    def _write_inline_tag(fp, tag, classes = []):
        _AA_Reports_Internal._begin_tag(fp, tag)
        _AA_Reports_Internal._write_classes(fp, classes)
        _AA_Reports_Internal._end_tag(fp)

    @staticmethod
    def _write_title(fp, title):
        _AA_Reports_Internal._write_inline_tag(fp, _AA_Reports_Internal._title_tag, _AA_Reports_Internal._title_classes)

        fp.write(title)

        _AA_Reports_Internal._close_tag(fp, _AA_Reports_Internal._title_tag)

    @staticmethod
    def _write_path(fp, path):
        _AA_Reports_Internal._write_inline_tag(fp, _AA_Reports_Internal._path_tag, _AA_Reports_Internal._path_classes)

        fp.write(path)

        _AA_Reports_Internal._close_tag(fp, _AA_Reports_Internal._path_tag)

    @staticmethod
    def _write_section_header(fp, title, path):
        _AA_Reports_Internal._write_inline_tag(fp, _AA_Reports_Internal._header_tag, _AA_Reports_Internal._header_classes)

        _AA_Reports_Internal._write_title(fp, title)
        _AA_Reports_Internal._write_path(fp, path)

        _AA_Reports_Internal._close_tag(fp, _AA_Reports_Internal._header_tag)

    @staticmethod
    def _write_result(fp, result):
        _AA_Reports_Internal._write_inline_tag(fp, _AA_Reports_Internal._result_tag, _AA_Reports_Internal._result_classes)
        
        fp.write(result)

        _AA_Reports_Internal._close_tag(fp, _AA_Reports_Internal._result_tag)

    @staticmethod
    def _write_raw(fp, raw):
        _AA_Reports_Internal._write_inline_tag(fp, _AA_Reports_Internal._raw_tag, _AA_Reports_Internal._raw_classes)
        
        for line in raw:
            fp.write(line + '<br/>')

        _AA_Reports_Internal._close_tag(fp, _AA_Reports_Internal._raw_tag)

    @staticmethod
    def _write_section(fp, title, path, result, raw):
        _AA_Reports_Internal._write_inline_tag(fp, _AA_Reports_Internal._audit_tag, _AA_Reports_Internal._audit_classes)
        
        _AA_Reports_Internal._write_section_header(fp, title, path)
        _AA_Reports_Internal._write_result(fp, result)
        _AA_Reports_Internal._write_raw(fp, raw)

        _AA_Reports_Internal._close_tag(fp, _AA_Reports_Internal._audit_tag)

    @staticmethod
    def _generate_report(path = AA_Constants.file_path_audit_directory, depends = {}, **kwargs):
        fp = open(os.path.join(path, "report.html"), "w+")

        depends_scripts = default_scripts
        depends_styles = default_styles
        depends_metas = default_metas
        
        if "scripts" in depends:
            depends_scripts += depends["scripts"]

        if "styles" in depends:
            depends_styles += depends["styles"]

        if "metas" in depends:
            depends_metas += depends["metas"]

        _AA_Reports_Internal._begin_report(fp, scripts = depends_scripts, styles = depends_styles, metas = depends_metas)
        
        for audit, data in kwargs.items():
            raw, path = data
            jdata = load_json_file(path)
            result = ""

            title = "(Unknown Audit)"

            if audit == AA_Constants.audit_type_network:
                title = "Network Scan"
                result = "When a software 'listens' on your device, it means it is waiting to receive information from another. Listening for anybody to speak to your computer can be dangerous.<br/><br/>"
                result += "Based on our analysis, you are currently running " + str(sum([len(jdata[r]) for r in jdata])) + " processes that are listening.<br/><br/>"
                result += "Our recommended course of action is to check if you are running any software that commmunicates on a network. Disable your internet connection and test if your machine continues to operate the same.<br/><br/>"
            elif audit == AA_Constants.audit_type_password:
                title = "Password Storage"
                result = "It is never smart to store passwords on a device, and especially without encryption and in an obvious file, like 'passwords.txt.'<br/><br/>"
                result += "Based on our analysis, your device contains " + str(sum([len(jdata[r]) for r in jdata])) + " files that may store passwords.<br/><br/>"
                result += "Our recommended course of action is to review the files listed below as soon as possible, and if any contain passwords, move that password to a physical document, delete the file safely, and ensure it is erased from your Trash.<br/><br/>"
            elif audit == AA_Constants.audit_type_services:
                title = "Service Scan"
                result = "Malicious software can do work in the background as a service, and well-meaning software can accidentally open you up to vulnerabilities.<br/><br/>"
                result += "Most legitimate software implements a particular type of 'status check' that returns information about the service. Those that do not may be malicious.<br/><br/>"
                result += "Based on our analysis, your device contains " + str(sum([sum([1 for s in jdata[r] if s["status"] == "-"]) for r in jdata])) + " services that do not implement status.<br/><br/>"
                result += "Our recommended course of action is to review the below services and identify any that are unfamiliar. For those that are unfamiliar, perform your own research to determine if they may be malicious. Remove malicious software ASAP.<br/><br/>"
            elif audit == AA_Constants.audit_type_password_policy:
                title = "Password Policy"
                result = "Passwords are the keys to the kingdom. If your password is easy to guess, never expires, and has not been changed recently, it is likely weak.<br/><br/>"

                if jdata[path][0]["Password_expires"] == "never":
                    result += "Based on our analysis, your password never expires.<br/><br/>"
                    if jdata[path][0]["Maximum_number_of_days_between_password_change"] == "99999":
                        result += "Your password also never rotates.<br/><br/>"
                        result += "Our recommended course of action is to enable password expiry and rotation for maximum password security.<br/><br/>"
                    else:
                        result += "Our recommended course of action is to enable password expiry for maximum password security.<br/><br/>"
                elif jdata[path][0]["Maximum_number_of_days_between_password_change"] == "99999":
                    result += "Based on our analysis, your password never rotates.<br/><br/>"
                    result += "Our recommended course of action is to enable password rotation for maximum password security.<br/><br/>"
            elif audit == AA_Constants.audit_type_network_card:
                title = "Network Card"

            _AA_Reports_Internal._write_section(fp, title, os.path.join(path, audit), result, raw)

        _AA_Reports_Internal._end_report(fp)

def generate_report(path = AA_Constants.file_path_audit_directory, **kwargs):
        _AA_Reports_Internal._generate_report(path, **kwargs)
