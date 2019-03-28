import os
import AA_Constants

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
            raw = data
            result = ""

            title = "(Unknown Audit)"

            if audit == AA_Constants.audit_type_network:
                title = "Network Scan"
            elif audit == AA_Constants.audit_type_password:
                title = "Password Storage"
            elif audit == AA_Constants.audit_type_services:
                title = "Service Scan"
            elif audit == AA_Constants.audit_type_password_policy:
                title = "Password Policy"
            elif audit == AA_Constants.audit_type_network_card:
                title = "Network Card"

            _AA_Reports_Internal._write_section(fp, title, os.path.join(path, audit), result, raw)

        _AA_Reports_Internal._end_report(fp)

def generate_report(path = AA_Constants.file_path_audit_directory, **kwargs):
        _AA_Reports_Internal._generate_report(path, **kwargs)
