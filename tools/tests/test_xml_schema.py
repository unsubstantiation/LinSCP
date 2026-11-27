"""Validate documented fixtures and an optional actual logger output against the XSD."""
import os
import pathlib
import unittest

try:
    import xmlschema
except ImportError:
    xmlschema = None

ROOT = pathlib.Path(__file__).resolve().parents[2]


@unittest.skipUnless(xmlschema, 'xmlschema dependency not installed')
class XmlSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema = xmlschema.XMLSchema(ROOT / 'docs/linscp-session-1.0.xsd')

    def test_shipped_fixtures(self):
        for name in ('action-log-success.xml', 'action-log-error.xml'):
            with self.subTest(name=name):
                self.schema.validate(ROOT / 'fixtures/xml' / name)

    def test_rejects_invalid_result(self):
        data = (ROOT / 'fixtures/xml/action-log-success.xml').read_text()
        self.assertIn('success="true"', data)
        with self.assertRaises(xmlschema.XMLSchemaValidationError):
            self.schema.validate(data.replace('success="true"', 'success="not-a-boolean"', 1))

    def test_generated_logger_output_when_requested(self):
        path = os.environ.get('LINSCP_XML_SCHEMA_TEST_OUTPUT')
        if not path:
            self.skipTest('logger output not requested')
        self.schema.validate(pathlib.Path(path))


if __name__ == '__main__':
    unittest.main()
