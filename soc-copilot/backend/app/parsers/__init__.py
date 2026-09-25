from app.models.alert import AlertSource
from app.parsers.base import AlertParser
from app.parsers.generic import GenericParser
from app.parsers.suricata import SuricataParser
from app.parsers.wazuh import WazuhParser
from app.parsers.zeek import ZeekParser


_PARSERS: dict[AlertSource, AlertParser] = {
    AlertSource.WAZUH: WazuhParser(),
    AlertSource.SURICATA: SuricataParser(),
    AlertSource.ZEEK: ZeekParser(),
    AlertSource.GENERIC: GenericParser(),
}


def get_parser(source: AlertSource) -> AlertParser:
    """Return the parser for a source, falling back to the generic one."""
    return _PARSERS.get(source, _PARSERS[AlertSource.GENERIC])
