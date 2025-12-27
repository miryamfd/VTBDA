from fpdf import FPDF
from datetime import datetime
from database import VulnerabilityDB
from analyze import VulnerabilityAnalyzer
import matplotlib.pyplot as plt
import io
import os

def _add_cover_page(self, pdf):
    """Ajouter la page de garde"""
    pdf.add_page()
    
    # Support UTF-8 pour les accents
    try:
        pdf.add_font('DejaVu', '', 'DejaVuSansCondensed.ttf', uni=True)
        pdf.set_font('DejaVu', '', 12)
    except:
        # Fallback sur Arial si DejaVu pas disponible
        pdf.set_font('Arial', '', 12)
    
    # ... reste du code

class VulnerabilityCharts:
    """Classe pour générer des graphiques de vulnérabilités"""
    
    @staticmethod
    def create_severity_pie_chart(output_path='severity_chart.png'):
        """Créer un graphique circulaire de la distribution par sévérité"""
        db = VulnerabilityDB()
        severity_stats = db.get_severity_stats()
        
        labels = list(severity_stats.keys())
        sizes = [severity_stats[s]['count'] for s in labels]
        colors = {
            'CRITICAL': '#e74c3c',
            'HIGH': '#f39c12',
            'MEDIUM': '#3498db',
            'LOW': '#2ecc71',
            'NONE': '#95a5a6'
        }
        chart_colors = [colors.get(label, '#95a5a6') for label in labels]
        
        plt.figure(figsize=(10, 6))
        plt.pie(sizes, labels=labels, colors=chart_colors, autopct='%1.1f%%', startangle=90)
        plt.title('Distribution des Vulnerabilites par Severite')
        plt.axis('equal')
        plt.savefig(output_path, bbox_inches='tight', dpi=150)
        plt.close()
        
        return output_path
    
    @staticmethod
    def create_trends_bar_chart(output_path='trends_chart.png', days=30):
        """Créer un graphique en barres des tendances"""
        db = VulnerabilityDB()
        trends = db.get_trends(days=days)
        
        if not trends:
            return None
        
        components = list(trends.keys())[:10]
        counts = [trends[c] for c in components]
        
        plt.figure(figsize=(12, 6))
        plt.bar(components, counts, color='#3498db')
        plt.xlabel('Composants')
        plt.ylabel('Nombre de mentions')
        plt.title(f'Top 10 Composants Affectes ({days} derniers jours)')
        plt.xticks(rotation=45, ha='right')
        plt.tight_layout()
        plt.savefig(output_path, bbox_inches='tight', dpi=150)
        plt.close()
        
        return output_path
    
    @staticmethod
    def create_timeline_chart(output_path='timeline_chart.png', days=30):
        """Créer un graphique d'évolution temporelle"""
        df = VulnerabilityAnalyzer.get_vulnerabilities_dataframe(days=days)
        
        if df.empty:
            return None
        
        import pandas as pd
        df['published_date'] = pd.to_datetime(df['published_date'])
        df['date'] = df['published_date'].dt.date
        daily_counts = df.groupby('date').size()
        
        plt.figure(figsize=(12, 6))
        daily_counts.plot(kind='line', marker='o', color='#e74c3c')
        plt.xlabel('Date')
        plt.ylabel('Nombre de vulnerabilites')
        plt.title(f'Evolution des Vulnerabilites ({days} derniers jours)')
        plt.xticks(rotation=45)
        plt.grid(True, alpha=0.3)
        plt.tight_layout()
        plt.savefig(output_path, bbox_inches='tight', dpi=150)
        plt.close()
        
        return output_path


class PDFReportGenerator:
    """Classe pour générer des rapports PDF"""
    
    def __init__(self):
        self.db = VulnerabilityDB()
        self.charts = VulnerabilityCharts()
    
    def generate_report(self, filename='rapport_veille.pdf'):
        """Générer un rapport PDF complet"""
        
        # Créer le PDF
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=15)
        
        # Page 1: Page de garde
        self._add_cover_page(pdf)
        
        # Page 2: Statistiques générales
        self._add_statistics_page(pdf)
        
        # Page 3: Graphiques
        self._add_charts_page(pdf)
        
        # Page 4: Vulnérabilités critiques
        self._add_critical_vulnerabilities_page(pdf)
        
        # Page 5: Top composants
        self._add_top_components_page(pdf)
        
        # Sauvegarder le PDF
        pdf.output(filename)
        return filename
    
    def _add_cover_page(self, pdf):
        """Ajouter la page de garde"""
        pdf.add_page()
        
        # Titre
        pdf.set_font('Arial', 'B', 24)
        pdf.cell(0, 60, '', 0, 1)  # Espace en haut
        pdf.cell(0, 20, 'Rapport de Veille', 0, 1, 'C')
        pdf.cell(0, 15, 'DevSecOps & CI/CD', 0, 1, 'C')
        
        # Date
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 10, '', 0, 1)
        pdf.cell(0, 10, f'Genere le {datetime.now().strftime("%d/%m/%Y")}', 0, 1, 'C')
        
        # Informations
        pdf.cell(0, 40, '', 0, 1)
        pdf.set_font('Arial', '', 10)
        pdf.cell(0, 8, 'Outil de Veille Technologique', 0, 1, 'C')
        pdf.cell(0, 8, 'Projet VTBDA', 0, 1, 'C')
    
    def _add_statistics_page(self, pdf):
        """Ajouter la page des statistiques"""
        pdf.add_page()
        
        # Titre
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Statistiques Globales', 0, 1)
        pdf.ln(5)
        
        # Récupérer les statistiques
        stats = VulnerabilityAnalyzer.get_statistics()
        severity_stats = self.db.get_severity_stats()
        
        # Statistiques principales
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'Nombre total de vulnerabilites', 0, 1)
        pdf.set_font('Arial', '', 12)
        pdf.cell(0, 8, f'  {stats["total_vulnerabilities"]}', 0, 1)
        pdf.ln(3)
        
        # Distribution par sévérité
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'Distribution par severite:', 0, 1)
        pdf.set_font('Arial', '', 11)
        
        for severity, data in severity_stats.items():
            pdf.cell(0, 7, f'  {severity}: {data["count"]} ({data["percentage"]}%)', 0, 1)
        
        pdf.ln(5)
        
        # Statistiques des bases
        total_counts = self.db.get_total_count()
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'Repartition par source:', 0, 1)
        pdf.set_font('Arial', '', 11)
        pdf.cell(0, 7, f'  CVE generales: {total_counts["cve_count"]}', 0, 1)
        pdf.cell(0, 7, f'  Vulnerabilites de packages: {total_counts["package_count"]}', 0, 1)
    
    def _add_charts_page(self, pdf):
        """Ajouter la page des graphiques"""
        pdf.add_page()
        
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Graphiques d\'Analyse', 0, 1)
        pdf.ln(5)
        
        # Générer les graphiques
        severity_chart = self.charts.create_severity_pie_chart('temp_severity.png')
        trends_chart = self.charts.create_trends_bar_chart('temp_trends.png')
        
        # Ajouter les graphiques au PDF
        if severity_chart and os.path.exists(severity_chart):
            pdf.image(severity_chart, x=10, y=40, w=190)
            os.remove(severity_chart)
        
        pdf.add_page()
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Tendances par Composant', 0, 1)
        pdf.ln(5)
        
        if trends_chart and os.path.exists(trends_chart):
            pdf.image(trends_chart, x=10, y=40, w=190)
            os.remove(trends_chart)
    
    def _add_critical_vulnerabilities_page(self, pdf):
        """Ajouter la page des vulnérabilités critiques"""
        pdf.add_page()
        
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Vulnerabilites Critiques', 0, 1)
        pdf.ln(5)
        
        # Récupérer les vulnérabilités critiques
        critical_vulns = VulnerabilityAnalyzer.get_critical_vulnerabilities(limit=10)
        
        if not critical_vulns:
            pdf.set_font('Arial', '', 11)
            pdf.cell(0, 8, 'Aucune vulnerabilite critique detectee.', 0, 1)
            return
        
        pdf.set_font('Arial', '', 10)
        
        for vuln in critical_vulns:
            # CVE ID
            pdf.set_font('Arial', 'B', 11)
            pdf.cell(0, 7, vuln['cve_id'], 0, 1)
            
            # Titre
            pdf.set_font('Arial', '', 10)
            pdf.multi_cell(0, 5, f'Titre: {vuln["title"][:100]}...')
            
            # Score CVSS
            pdf.cell(0, 5, f'Score CVSS: {vuln["cvss_score"]}', 0, 1)
            
            # Date
            if vuln['published_date']:
                date_str = str(vuln['published_date'])[:10]
                pdf.cell(0, 5, f'Date: {date_str}', 0, 1)
            
            pdf.ln(3)
    
    def _add_top_components_page(self, pdf):
        """Ajouter la page des composants les plus affectés"""
        pdf.add_page()
        
        pdf.set_font('Arial', 'B', 16)
        pdf.cell(0, 10, 'Composants les Plus Affectes', 0, 1)
        pdf.ln(5)
        
        # Récupérer les top composants
        top_components = VulnerabilityAnalyzer.get_top_affected_components(limit=15)
        
        if not top_components:
            pdf.set_font('Arial', '', 11)
            pdf.cell(0, 8, 'Aucun composant affecte detecte.', 0, 1)
            return
        
        # Tableau des composants
        pdf.set_font('Arial', 'B', 11)
        pdf.cell(120, 8, 'Composant', 1, 0, 'C')
        pdf.cell(60, 8, 'Nombre de mentions', 1, 1, 'C')
        
        pdf.set_font('Arial', '', 10)
        for component in top_components:
            pdf.cell(120, 7, component['component'], 1, 0)
            pdf.cell(60, 7, str(component['count']), 1, 1, 'C')
        
        pdf.ln(5)
        
        # Conclusion
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(0, 8, 'Recommandations:', 0, 1)
        pdf.set_font('Arial', '', 10)
        pdf.multi_cell(0, 5, '- Surveiller regulierement les mises a jour de securite\n'
                            '- Appliquer les correctifs disponibles\n'
                            '- Mettre en place un processus de gestion des vulnerabilites\n'
                            '- Former les equipes aux bonnes pratiques DevSecOps')


if __name__ == '__main__':
    # Test de génération de rapport
    generator = PDFReportGenerator()
    filename = generator.generate_report('test_rapport.pdf')
    print(f"Rapport genere: {filename}")