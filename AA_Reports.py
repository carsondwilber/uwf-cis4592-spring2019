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
        fp.write('\t\t<script type="text/javascript" src="' + src + '" />')

    @staticmethod
    def _write_scripts(fp, srcs):
        for src in srcs:
            _write_script(fp, src)

    @staticmethod
    def _write_style(fp, style):
        fp.write('\t\t<link rel="stylesheet" type="text/css" href="' + style + '" />')

    @staticmethod
    def _write_styles(fp, styles):
        for style in styles:
            _write_style(fp, style)

    @staticmethod
    def _write_meta_fields(fp, fields):
        for field, value in fields:
            fp.write(field + '=' + value + ' ')

    @staticmethod
    def _write_meta(fp, meta):
        fp.write('\t\t<meta ')
        _write_meta_fields(fp, meta)
        fp.write('/>')

    @staticmethod
    def _write_dependencies(fp, **kwargs):
        for key, item in kwargs:
            if key == "scripts":
                _write_scripts(fp, item)
            elif key == "styles":
                _write_styles(fp, item)
            elif key == "meta":
                _write_metas(fp, item)
            else:
                _write_links(fp, item)

    @staticmethod
    def _begin_document(fp):
        fp.write('<!DOCTYPE html>')
        fp.write('<html>')

    @staticmethod
    def _write_header(fp, kwargs):
        fp.write('\t<head>')
        _write_dependencies(fp, kwargs)
        fp.write('\t</head>')

    @staticmethod
    def _begin_body(fp):
        fp.write('\t<body>')

    @staticmethod
    def _begin_report(fp, kwargs):
        _begin_document(fp)
        _write_header(fp, kwargs)
        _begin_body(fp)

    @staticmethod
    def _end_report(fp):
        _end_body(fp)
        _end_document(fp)

    @staticmethod
    def generate_report(path, audit, data, depends_scripts = default_scripts, depends_styles = default_styles, depends_metas = default_metas):
        fp = open(os.join(path, audit), "w+")

        _begin_report(fp, scripts = depends_scripts, styles = depends_styles, metas = depends_metas)

        if audit == AA_Constants.audit_type_network:
            # TODO: Generate HTML5/CSS3/JavaScript report for network.
        elif audit == AA_Constants.audit_type_password:
            # TODO: Generate HTML5/CSS3/JavaScript report for password.
        elif audit == AA_Constants.audit_type_services:
            # TODO: Generate HTML5/CSS3/JavaScript report for services. 
        elif audit == AA_Constants.audit_type_password_policy:
            # TODO: Generate HTML5/CSS3/JavaScript report for password_policy.
        elif audit == AA_Constants.audit_type_network_card:
            # TODO: Generate HTML5/CSS3/JavaScript report for network_card.

        _end_report(fp)

def generate_reports(path, **kwargs):
    for audit, data in kwargs:
        _AA_Reports_Internal.generate_report(path, audit, data)
