import os
import AA_Constants

default_scripts = ["jquery.js"]
default_styles = []
default_metas = []

class _AA_Reports_Internal:
    _audit_tag = "div"
    _audit_classes = "audit-section"

    _result_tag = "div"
    _result_classes = "script-result"
    
    _raw_tag = "div"
    _raw_classes = "raw-output"

    @staticmethod
    def _write_script(fp, src):
        fp.write('\t\t<script type="text/javascript" src="' + src + '" />\n')

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
    def _generate_report(path, depends = {}, **kwargs):
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
            if audit == AA_Constants.audit_type_network:
                # TODO: Generate HTML5/CSS3/JavaScript report for network.
                assert(True)
            elif audit == AA_Constants.audit_type_password:
                # TODO: Generate HTML5/CSS3/JavaScript report for password.
                assert(True)
            elif audit == AA_Constants.audit_type_services:
                # TODO: Generate HTML5/CSS3/JavaScript report for services. 
                assert(True)
            elif audit == AA_Constants.audit_type_password_policy:
                # TODO: Generate HTML5/CSS3/JavaScript report for password_policy.
                assert(True)
            elif audit == AA_Constants.audit_type_network_card:
                # TODO: Generate HTML5/CSS3/JavaScript report for network_card.
                assert(True)

        _AA_Reports_Internal._end_report(fp)

def generate_report(path, **kwargs):
        _AA_Reports_Internal._generate_report(path, **kwargs)
