import unittest
from audit import summarize_xml
from laboratoire import run_lab


class AuditTests(unittest.TestCase):
    def test_lab_corrections_and_retests(self):
        report = run_lab()
        sql, passwords = report['controles']
        self.assertTrue(sql['preuve']['connexion_sans_mot_de_passe_valide'])
        self.assertFalse(sql['preuve_apres']['injection_acceptee'])
        self.assertTrue(sql['preuve_apres']['connexion_valide'])
        self.assertFalse(sql['preuve_apres']['mauvais_mot_de_passe_accepte'])
        self.assertEqual(passwords['preuve_apres']['tentatives'], ['REFUSÉ'] * 3 + ['BLOQUÉ'] * 2)
        self.assertTrue(all(c['retest'] == 'CORRIGÉ POUR CE TEST' for c in report['controles']))

    def test_missing_and_invalid_results_remain_unknown(self):
        for xml in ('<nmaprun/>', '<nmaprun>'):
            self.assertEqual(summarize_xml(xml, ['ftp-anon'], 0)[0]['etat'], 'NON VÉRIFIÉ')

    def test_anonymous_access_requires_positive_evidence(self):
        xml = '<nmaprun><host><script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)"/></host></nmaprun>'
        self.assertEqual(summarize_xml(xml, ['ftp-anon'], 0)[0]['etat'], 'ACCÈS ANONYME CONFIRMÉ')
        self.assertEqual(summarize_xml(xml, ['ftp-anon'], 1)[0]['etat'], 'NON VÉRIFIÉ')

    def test_not_vulnerable_is_not_misclassified(self):
        template = '<nmaprun><host><script id="smb-vuln-ms17-010" output="result"><table><elem key="state">{}</elem></table></script></host></nmaprun>'
        self.assertEqual(summarize_xml(template.format('NOT VULNERABLE'), ['smb-vuln-ms17-010'], 0)[0]['etat'], 'À EXAMINER')
        self.assertEqual(summarize_xml(template.format('VULNERABLE'), ['smb-vuln-ms17-010'], 0)[0]['etat'], 'VULNÉRABILITÉ SIGNALÉE PAR NMAP')

    def test_open_port_is_not_a_vulnerability(self):
        xml = '<nmaprun><host><ports><port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port></ports></host></nmaprun>'
        self.assertEqual(summarize_xml(xml, [], 0)[0]['etat'], 'SERVICE ACCESSIBLE')


if __name__ == '__main__':
    unittest.main()
