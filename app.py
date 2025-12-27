from flask import Flask, render_template, request, jsonify, send_file
from config import DevelopmentConfig
from database import VulnerabilityDB
from analyze import VulnerabilityAnalyzer
from charts import PDFReportGenerator
from datetime import datetime
import os

# Créer l'application Flask
app = Flask(__name__)
app.config.from_object(DevelopmentConfig)

# Initialiser la base de données
db = VulnerabilityDB()

# Import automation après la création de l'app
try:
    from automation import automation_system, start_automation_on_startup
    automation_available = True
except ImportError:
    automation_available = False
    print("Module automation non disponible")

# Démarrer l'automatisation si activée
if automation_available:
    start_automation_on_startup()


# Routes principales

@app.route('/')
def index():
    """Page d'accueil"""
    stats = VulnerabilityAnalyzer.get_statistics()
    trends = VulnerabilityAnalyzer.get_top_affected_components(limit=5)
    
    return render_template('index.html', stats=stats, trends=trends)


@app.route('/search', methods=['GET', 'POST'])
def search():
    """Page de recherche"""
    results = []
    
    if request.method == 'POST':
        # Récupérer les paramètres de recherche
        severity = request.form.get('severity') or None
        component = request.form.get('component') or None
        days = request.form.get('days')
        
        # Convertir days en entier si présent
        days = int(days) if days else None
        
        # Filtrer les vulnérabilités
        results = VulnerabilityAnalyzer.filter_vulnerabilities(
            severity=severity,
            component=component,
            days=days
        )
    
    return render_template('search.html', results=results)


@app.route('/reports')
def reports():
    """Page des rapports"""
    stats = VulnerabilityAnalyzer.get_statistics()
    severity_breakdown = VulnerabilityAnalyzer.get_severity_distribution()
    trends = VulnerabilityAnalyzer.get_trends(days=30)
    
    # Nouvelles données d'analyse
    charts = VulnerabilityAnalyzer.generate_matplotlib_charts(days=30)
    text_analysis = VulnerabilityAnalyzer.get_text_vectorization()
    summaries = VulnerabilityAnalyzer.generate_descriptions_summary()
    
    return render_template('reports.html',
                         stats=stats,
                         severity_breakdown=severity_breakdown,
                         trends=trends,
                         charts=charts,
                         text_analysis=text_analysis,
                         summaries=summaries)


@app.route('/admin')
def admin():
    """Page d'administration"""
    return render_template('admin.html')


@app.route('/alerts')
def alerts():
    """Page d'inscription aux alertes"""
    return render_template('alerts.html')


@app.route('/add_test_data')
def add_test_data_route():
    """Ajouter des données de test via l'interface web"""
    from add_test_data import add_test_data
    try:
        add_test_data()
        return jsonify({'status': 'success', 'message': 'Donnees de test ajoutees'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# API Routes

@app.route('/api/vulnerabilities', methods=['GET'])
def api_vulnerabilities():
    """API pour récupérer les vulnérabilités (JSON)"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    # Récupérer toutes les vulnérabilités
    df = db.get_all_vulnerabilities_combined()
    
    # Pagination manuelle
    total = len(df)
    start = (page - 1) * per_page
    end = start + per_page
    paginated_df = df.iloc[start:end]
    
    # Convertir en liste de dictionnaires
    vulnerabilities = []
    for _, row in paginated_df.iterrows():
        vulnerabilities.append({
            'id': int(row.name) if hasattr(row, 'name') else 0,
            'cve_id': row['cve_id'],
            'title': row['title'],
            'severity': row['severity'],
            'cvss_score': row['cvss_score'],
            'component': row['affected_component'],
            'url': row['url']
        })
    
    data = {
        'total': total,
        'pages': (total + per_page - 1) // per_page,
        'current_page': page,
        'vulnerabilities': vulnerabilities
    }
    
    return jsonify(data)


@app.route('/api/statistics', methods=['GET'])
def api_statistics():
    """API pour les statistiques"""
    return jsonify(VulnerabilityAnalyzer.get_statistics())


@app.route('/api/subscribe-alerts', methods=['POST'])
def subscribe_alerts():
    """API pour s'inscrire aux alertes"""
    data = request.get_json()
    
    # TODO: Stocker dans une table "subscriptions" en BDD
    # Pour l'instant, simuler le succès
    
    return jsonify({
        'status': 'success',
        'message': f"Abonnement cree pour {data.get('email')}"
    })


@app.route('/generate_pdf')
def generate_pdf():
    """Générer et télécharger un rapport PDF"""
    try:
        pdf_generator = PDFReportGenerator()
        filename = pdf_generator.generate_report()
        
        return send_file(filename,
                        as_attachment=True,
                        download_name=f"rapport_veille_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                        mimetype='application/pdf')
    except Exception as e:
        return f"Erreur lors de la generation du PDF: {str(e)}", 500


# Routes d'automatisation

@app.route('/automation/start')
def start_automation():
    """Démarrer l'automatisation"""
    if not automation_available:
        return jsonify({'status': 'error', 'message': 'Module automation non disponible'}), 500
    
    try:
        automation_system.start_automation()
        return jsonify({'status': 'success', 'message': 'Automatisation demarree'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/automation/stop')
def stop_automation():
    """Arrêter l'automatisation"""
    if not automation_available:
        return jsonify({'status': 'error', 'message': 'Module automation non disponible'}), 500
    
    try:
        automation_system.stop_automation()
        return jsonify({'status': 'success', 'message': 'Automatisation arretee'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/automation/status')
def automation_status():
    """Vérifier le statut de l'automatisation"""
    if not automation_available:
        return jsonify({
            'is_running': False,
            'next_runs': [],
            'error': 'Module automation non disponible'
        })
    
    import schedule
    return jsonify({
        'is_running': automation_system.is_running,
        'next_runs': [
            {'job': str(job), 'next_run': str(job.next_run)}
            for job in schedule.jobs
        ]
    })


@app.route('/automation/run-collectors')
def run_collectors():
    """Exécuter manuellement les collecteurs"""
    if not automation_available:
        return jsonify({'status': 'error', 'message': 'Module automation non disponible'}), 500
    
    try:
        automation_system.run_manual_collection()
        return jsonify({'status': 'success', 'message': 'Collecteurs executes manuellement'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


@app.route('/automation/test-alerts')
def test_alerts():
    """Tester les alertes email"""
    if not automation_available:
        return jsonify({'status': 'error', 'message': 'Module automation non disponible'}), 500
    
    try:
        automation_system.run_manual_alerts()
        return jsonify({'status': 'success', 'message': 'Test des alertes envoye'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500


# Gestion des erreurs

@app.errorhandler(404)
def not_found(error):
    return render_template('404.html'), 404


@app.errorhandler(500)
def server_error(error):
    return render_template('500.html'), 500


if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)