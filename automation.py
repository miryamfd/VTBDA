import os
import schedule
import time
from datetime import datetime
import threading


class AutomationSystem:
    """Système d'automatisation avec vrais collecteurs"""
    
    def __init__(self):
        self.is_running = False
        self.thread = None
    
    def collect_osv_github_data(self):
        """Collecte OSV + GitHub"""
        print(f"\n🔄 Collecte OSV+GitHub démarrée à {datetime.now()}")
        
        try:
            from collectors.osv_github_collector import OSVGitHubCollector
            
            collector = OSVGitHubCollector()
            stats = collector.run()
            
            print(f"✅ Collecte OSV+GitHub terminée : {stats['inserted']} nouvelles vulnérabilités")
            
            return stats
        
        except Exception as e:
            print(f"❌ Erreur collecte OSV+GitHub : {e}")
            return {'error': str(e)}
    
    def run_all_collectors(self):
        """Exécuter tous les collecteurs"""
        print(f"\n{'='*70}")
        print(f"🚀 DÉMARRAGE DE TOUS LES COLLECTEURS")
        print(f"{'='*70}")
        
        # OSV + GitHub
        osv_stats = self.collect_osv_github_data()
        
        print(f"\n{'='*70}")
        print(f"✅ TOUS LES COLLECTEURS TERMINÉS")
        print(f"{'='*70}\n")
        
        return {
            'osv_github': osv_stats
        }
    
    def send_daily_alerts(self):
        """Vérifier et envoyer les alertes quotidiennes"""
        print(f"📧 Vérification des alertes quotidiennes à {datetime.now()}")
        
        # TODO: Implémenter logique d'alertes
        # Pour l'instant, juste un log
    
    def send_weekly_report(self):
        """Générer et envoyer le rapport hebdomadaire"""
        print(f"📊 Génération du rapport hebdomadaire à {datetime.now()}")
        
        # TODO: Implémenter génération rapport
        # Pour l'instant, juste un log
    
    def setup_schedule(self):
        """Configurer le calendrier d'automatisation"""
        # Collecte toutes les 6 heures
        schedule.every(6).hours.do(self.run_all_collectors)
        
        # Alertes quotidiennes à 9h
        schedule.every().day.at("09:00").do(self.send_daily_alerts)
        
        # Rapport hebdomadaire le lundi à 8h
        schedule.every().monday.at("08:00").do(self.send_weekly_report)
        
        print("✅ Calendrier d'automatisation configuré :")
        print("  → Collecte : toutes les 6 heures")
        print("  → Alertes  : tous les jours à 9h00")
        print("  → Rapport  : tous les lundis à 8h00")
    
    def start_automation(self):
        """Démarrer le système d'automatisation"""
        if self.is_running:
            print("⚠️  L'automatisation est déjà en cours")
            return
        
        print("\n🚀 Démarrage du système d'automatisation...")
        self.setup_schedule()
        self.is_running = True
        
        self.thread = threading.Thread(target=self.run_scheduler, daemon=True)
        self.thread.start()
        
        print("✅ Système d'automatisation démarré\n")
    
    def stop_automation(self):
        """Arrêter le système d'automatisation"""
        if not self.is_running:
            print("⚠️  L'automatisation n'est pas en cours")
            return
        
        print("\n🛑 Arrêt du système d'automatisation...")
        self.is_running = False
        schedule.clear()
        
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5)
        
        print("✅ Système d'automatisation arrêté\n")
    
    def run_scheduler(self):
        """Boucle principale du scheduler"""
        print("⏰ Scheduler démarré - en attente de tâches planifiées...")
        
        while self.is_running:
            try:
                schedule.run_pending()
                time.sleep(60)  # Vérifier toutes les minutes
            except Exception as e:
                print(f"❌ Erreur dans le scheduler : {str(e)}")
                time.sleep(300)  # Attendre 5 min avant de réessayer
        
        print("⏰ Scheduler arrêté")
    
    def run_manual_collection(self):
        """Exécuter une collecte manuelle"""
        print("\n🔧 Exécution manuelle des collecteurs...")
        stats = self.run_all_collectors()
        print("✅ Collecte manuelle terminée\n")
        return stats
    
    def run_manual_alerts(self):
        """Envoyer des alertes manuellement"""
        print("\n📧 Test des alertes...")
        self.send_daily_alerts()
        print("✅ Test des alertes terminé\n")


# Instance globale
automation_system = AutomationSystem()


def start_automation_on_startup():
    """Fonction à appeler au démarrage de l'application"""
    if os.getenv('ENABLE_AUTOMATION', 'false').lower() == 'true':
        automation_system.start_automation()
    else:
        print("ℹ️  Automatisation désactivée (définir ENABLE_AUTOMATION=true pour l'activer)")