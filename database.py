import sqlite3
import pandas as pd
from datetime import datetime
import os

class VulnerabilityDB:
    """
    Classe pour gérer la base de données SQLite des vulnérabilités
    Compatible avec le projet VTBDA - DevSecOps & CI/CD
    """
    
    def __init__(self, db_name='data/vulnerabilities.db'):
        """
        Initialiser la connexion à la base de données
        
        Args:
            db_name: Chemin vers le fichier .db
        """
        self.db_name = db_name
        
        # Créer dossier data/ s'il n'existe pas
        os.makedirs('data', exist_ok=True)
        
        # Créer tables si elles n'existent pas
        self.create_tables()
        print(f"✅ Base de données initialisée : {db_name}")
    
    def create_tables(self):
        """
        Créer les 3 tables nécessaires pour le projet
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        # TABLE 1 : CVE (vulnérabilités générales de NVD)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS cve_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve_id TEXT UNIQUE NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            cvss_score REAL,
            severity TEXT CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE')),
            published_date TEXT,
            modified_date TEXT,
            source TEXT DEFAULT 'NVD',
            url TEXT,
            collected_date TEXT DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # TABLE 2 : PACKAGES (npm, pip, maven, docker, kubernetes, github)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS package_vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            ecosystem TEXT CHECK(ecosystem IN ('npm','pip','maven','docker','kubernetes','github')),
            vulnerability_type TEXT,
            cvss_score REAL,
            severity TEXT CHECK(severity IN ('CRITICAL','HIGH','MEDIUM','LOW','NONE')),
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            published_date TEXT,
            discovered_date TEXT,
            affected_versions TEXT,
            patched_version TEXT,
            source TEXT,
            url TEXT,
            collected_date TEXT DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # TABLE 3 : SUPPLY-CHAIN (dépendances entre packages)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS supply_chain (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            parent_package TEXT NOT NULL,
            dependent_package TEXT NOT NULL,
            ecosystem TEXT,
            vulnerability_id INTEGER,
            impact_score INTEGER DEFAULT 0,
            FOREIGN KEY(vulnerability_id) REFERENCES package_vulnerabilities(id)
        )
        ''')
        
        # TABLE 4 : ARTICLES (pour stocker les articles/rapports)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            content TEXT,
            source TEXT,
            category TEXT,
            url TEXT,
            published_date TEXT,
            collected_date TEXT DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # TABLE 5 : TRENDS (tendances des mots-clés)
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS trends (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword TEXT NOT NULL,
            count INTEGER DEFAULT 1,
            severity_level TEXT,
            last_updated TEXT DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        
        # Index pour accélérer les recherches
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_cve_severity ON cve_vulnerabilities(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_pkg_severity ON package_vulnerabilities(severity)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_pkg_ecosystem ON package_vulnerabilities(ecosystem)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_pkg_name ON package_vulnerabilities(package_name)')
        
        conn.commit()
        conn.close()
        print("✅ Tables créées avec succès")
    
    # ========== FONCTIONS INSERT (Ajouter données) ==========
    
    def insert_cve(self, cve_data):
        """
        Ajouter une vulnérabilité CVE avec description complète
        
        Args:
            cve_data: Dictionnaire avec clés : cve_id, title, description, 
                     cvss_score, severity, published_date, url
        
        Returns:
            True si succès, False sinon
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT OR IGNORE INTO cve_vulnerabilities 
            (cve_id, title, description, cvss_score, severity, published_date, modified_date, url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                cve_data.get('cve_id'),
                cve_data.get('title', 'No title'),
                cve_data.get('description', 'No description available'),
                cve_data.get('cvss_score'),
                cve_data.get('severity'),
                cve_data.get('published_date'),
                cve_data.get('modified_date'),
                cve_data.get('url')
            ))
            conn.commit()
            return True
        except Exception as e:
            print(f"❌ Erreur insertion CVE : {e}")
            return False
        finally:
            conn.close()
    
    def insert_package_vulnerability(self, package_data):
        """
        Ajouter une vulnérabilité de package avec description complète
        
        Args:
            package_data: Dictionnaire avec toutes les infos du package
        
        Returns:
            ID de la vulnérabilité insérée ou None
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO package_vulnerabilities 
            (package_name, ecosystem, vulnerability_type, cvss_score, severity, 
             title, description, published_date, discovered_date, affected_versions, 
             patched_version, source, url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                package_data.get('package_name'),
                package_data.get('ecosystem'),
                package_data.get('vulnerability_type'),
                package_data.get('cvss_score'),
                package_data.get('severity'),
                package_data.get('title', 'No title'),
                package_data.get('description', 'No description available'),
                package_data.get('published_date'),
                package_data.get('discovered_date'),
                package_data.get('affected_versions'),
                package_data.get('patched_version'),
                package_data.get('source'),
                package_data.get('url')
            ))
            conn.commit()
            vuln_id = cursor.lastrowid
            return vuln_id
        except Exception as e:
            print(f"❌ Erreur insertion package : {e}")
            return None
        finally:
            conn.close()
    
    def insert_supply_chain(self, parent_package, dependent_package, ecosystem, vulnerability_id=None):
        """
        Ajouter une relation de dépendance supply-chain
        """
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO supply_chain 
            (parent_package, dependent_package, ecosystem, vulnerability_id)
            VALUES (?, ?, ?, ?)
            ''', (parent_package, dependent_package, ecosystem, vulnerability_id))
            conn.commit()
            return True
        except Exception as e:
            print(f"❌ Erreur insertion supply-chain : {e}")
            return False
        finally:
            conn.close()
    
    def insert_article(self, article_data):
        """Ajouter un article"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO articles (title, content, source, category, url, published_date)
            VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                article_data.get('title'),
                article_data.get('content'),
                article_data.get('source'),
                article_data.get('category'),
                article_data.get('url'),
                article_data.get('published_date')
            ))
            conn.commit()
            return True
        except Exception as e:
            print(f"❌ Erreur insertion article : {e}")
            return False
        finally:
            conn.close()
    
    def insert_trend(self, keyword, count=1, severity_level=None):
        """Ajouter une tendance"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
            INSERT INTO trends (keyword, count, severity_level)
            VALUES (?, ?, ?)
            ''', (keyword, count, severity_level))
            conn.commit()
            return True
        except Exception as e:
            print(f"❌ Erreur insertion trend : {e}")
            return False
        finally:
            conn.close()
    
    # ========== FONCTIONS GET (Récupérer données) ==========
    
    def get_all_cve(self):
        """Récupérer toutes les CVE"""
        conn = sqlite3.connect(self.db_name)
        df = pd.read_sql_query(
            "SELECT * FROM cve_vulnerabilities ORDER BY published_date DESC", 
            conn
        )
        conn.close()
        return df
    
    def get_all_packages(self):
        """Récupérer toutes les vulnérabilités de packages"""
        conn = sqlite3.connect(self.db_name)
        df = pd.read_sql_query(
            "SELECT * FROM package_vulnerabilities ORDER BY published_date DESC", 
            conn
        )
        conn.close()
        return df
    
    def get_all_vulnerabilities_combined(self):
        """
        Combiner CVE et Packages dans une seule vue
        Compatible avec l'interface actuelle
        """
        conn = sqlite3.connect(self.db_name)
        
        # Union des deux tables
        query = '''
        SELECT 
            cve_id,
            title,
            description,
            severity,
            cvss_score,
            NULL as affected_component,
            NULL as ecosystem,
            NULL as vulnerability_type,
            published_date,
            published_date as discovered_date,
            NULL as modified_date,
            source,
            url
        FROM cve_vulnerabilities
        
        UNION ALL
        
        SELECT 
            NULL as cve_id,
            title,
            description,
            severity,
            cvss_score,
            package_name as affected_component,
            ecosystem,
            vulnerability_type,
            published_date,
            discovered_date,
            NULL as modified_date,
            source,
            url
        FROM package_vulnerabilities
        
        ORDER BY published_date DESC
        '''
        
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    
    def get_packages_by_severity(self, severity):
        """Filtrer packages par sévérité"""
        conn = sqlite3.connect(self.db_name)
        query = "SELECT * FROM package_vulnerabilities WHERE severity = ? ORDER BY cvss_score DESC"
        df = pd.read_sql_query(query, conn, params=(severity,))
        conn.close()
        return df
    
    def get_packages_by_ecosystem(self, ecosystem):
        """Filtrer par écosystème"""
        conn = sqlite3.connect(self.db_name)
        query = "SELECT * FROM package_vulnerabilities WHERE ecosystem = ? ORDER BY published_date DESC"
        df = pd.read_sql_query(query, conn, params=(ecosystem,))
        conn.close()
        return df
    
    def search_vulnerabilities(self, severity=None, component=None, days=None):
        """
        Recherche multi-critères compatible avec l'interface Flask
        """
        conn = sqlite3.connect(self.db_name)
        
        # Construction de la requête dynamique
        conditions = []
        params = []
        
        base_query = '''
        SELECT 
            COALESCE(cve_id, 'PKG-' || package_name) as cve_id,
            title,
            description,
            severity,
            cvss_score,
            COALESCE(package_name, 'N/A') as affected_component,
            ecosystem,
            vulnerability_type,
            published_date,
            url
        FROM (
            SELECT cve_id, title, description, severity, cvss_score, 
                   NULL as package_name, NULL as ecosystem, NULL as vulnerability_type,
                   published_date, url
            FROM cve_vulnerabilities
            
            UNION ALL
            
            SELECT NULL as cve_id, title, description, severity, cvss_score,
                   package_name, ecosystem, vulnerability_type,
                   published_date, url
            FROM package_vulnerabilities
        )
        '''
        
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        
        if component:
            conditions.append("(package_name LIKE ? OR cve_id LIKE ?)")
            params.extend([f'%{component}%', f'%{component}%'])
        
        if days:
            conditions.append("julianday('now') - julianday(published_date) <= ?")
            params.append(days)
        
        if conditions:
            base_query += " WHERE " + " AND ".join(conditions)
        
        base_query += " ORDER BY published_date DESC"
        
        df = pd.read_sql_query(base_query, conn, params=params)
        conn.close()
        return df
    
    def get_supply_chain_impact(self, package_name):
        """Trouver tous les packages qui dépendent d'un package donné"""
        conn = sqlite3.connect(self.db_name)
        query = '''
        SELECT sc.parent_package, sc.dependent_package, sc.ecosystem, 
               pv.severity, pv.cvss_score, pv.description
        FROM supply_chain sc
        LEFT JOIN package_vulnerabilities pv ON sc.vulnerability_id = pv.id
        WHERE sc.dependent_package = ?
        '''
        df = pd.read_sql_query(query, conn, params=(package_name,))
        conn.close()
        return df
    
    # ========== FONCTIONS STATISTIQUES ==========
    
    def get_total_count(self):
        """Compter total de vulnérabilités"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM cve_vulnerabilities")
        cve_count = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM package_vulnerabilities")
        package_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'cve_count': cve_count,
            'package_count': package_count,
            'total': cve_count + package_count
        }
    
    def get_severity_stats(self):
        """Statistiques par sévérité"""
        conn = sqlite3.connect(self.db_name)
        
        query = '''
        SELECT severity, COUNT(*) as count
        FROM (
            SELECT severity FROM cve_vulnerabilities
            UNION ALL
            SELECT severity FROM package_vulnerabilities
        )
        GROUP BY severity
        '''
        
        cursor = conn.cursor()
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        
        stats = {}
        total = sum(r[1] for r in results)
        
        for severity, count in results:
            if severity:
                percentage = (count / total * 100) if total > 0 else 0
                stats[severity] = {
                    'count': count,
                    'percentage': round(percentage, 1)
                }
        
        return stats
    
    def get_top_components(self, limit=5):
        """Top composants affectés"""
        conn = sqlite3.connect(self.db_name)
        
        query = '''
        SELECT package_name as component, COUNT(*) as count
        FROM package_vulnerabilities
        WHERE package_name IS NOT NULL
        GROUP BY package_name
        ORDER BY count DESC
        LIMIT ?
        '''
        
        cursor = conn.cursor()
        cursor.execute(query, (limit,))
        results = cursor.fetchall()
        conn.close()
        
        return [{'component': r[0], 'count': r[1]} for r in results]
    
    def get_trends(self, days=30):
        """Tendances des derniers X jours"""
        conn = sqlite3.connect(self.db_name)
        
        query = '''
        SELECT package_name, COUNT(*) as count
        FROM package_vulnerabilities
        WHERE julianday('now') - julianday(discovered_date) <= ?
        AND package_name IS NOT NULL
        GROUP BY package_name
        ORDER BY count DESC
        '''
        
        cursor = conn.cursor()
        cursor.execute(query, (days,))
        results = cursor.fetchall()
        conn.close()
        
        return dict(results)
    
    def get_critical_vulnerabilities(self, limit=10):
        """Vulnérabilités critiques (CVSS >= 9.0)"""
        conn = sqlite3.connect(self.db_name)
        
        query = '''
        SELECT * FROM (
            SELECT cve_id, title, cvss_score, published_date, url
            FROM cve_vulnerabilities
            WHERE cvss_score >= 9.0
            
            UNION ALL
            
            SELECT 'PKG-' || package_name as cve_id, title, cvss_score, published_date, url
            FROM package_vulnerabilities
            WHERE cvss_score >= 9.0
        )
        ORDER BY cvss_score DESC, published_date DESC
        LIMIT ?
        '''
        
        cursor = conn.cursor()
        cursor.execute(query, (limit,))
        results = cursor.fetchall()
        conn.close()
        
        return [
            {
                'cve_id': r[0],
                'title': r[1],
                'cvss_score': r[2],
                'published_date': r[3],
                'url': r[4]
            }
            for r in results
        ]
    
    # ========== FONCTIONS UTILITAIRES ==========
    
    def clear_all_data(self):
        """ATTENTION : Supprimer TOUTES les données"""
        conn = sqlite3.connect(self.db_name)
        cursor = conn.cursor()
        
        cursor.execute("DELETE FROM cve_vulnerabilities")
        cursor.execute("DELETE FROM package_vulnerabilities")
        cursor.execute("DELETE FROM supply_chain")
        cursor.execute("DELETE FROM articles")
        cursor.execute("DELETE FROM trends")
        
        conn.commit()
        conn.close()
        print(" Toutes les données supprimées")
    
    def close(self):
        """Fermer la connexion"""
        pass  # SQLite n'a pas besoin de fermeture permanente


# Instance globale
db = VulnerabilityDB()


if __name__ == "__main__":
    """Tests de la base de données"""
    print("=== TEST DATABASE.PY ===\n")
    
    # Test 1 : Création
    print(" Base de données créée")
    
    # Test 2 : Statistiques
    stats = db.get_total_count()
    print(f" Total: {stats['total']} vulnérabilités")
    
    print("\n TOUS LES TESTS RÉUSSIS !")