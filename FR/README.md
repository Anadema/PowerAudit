# PowerAudit 3.0

> **Outil de relevé de configuration et d'audit de sécurité Windows — usage éthique et défensif uniquement.**

---

<div style="display: flex; gap: 20px; align-items: center;">
  <a href="https://raw.githubusercontent.com/Anadema/PowerAudit/refs/heads/main/Image/Menu_fr.jpg">
    <img src="https://raw.githubusercontent.com/Anadema/PowerAudit/refs/heads/main/Image/Menu_fr.jpg"
         style="height: 500px; width: auto;">
  </a>

  <a href="https://raw.githubusercontent.com/Anadema/PowerAudit/refs/heads/main/Image/Partial_report_fr.jpg">
    <img src="https://raw.githubusercontent.com/Anadema/PowerAudit/refs/heads/main/Image/Partial_report_fr.jpg"
         style="height: 500px; width: auto;">
  </a>
</div>

## Objectif

PowerAudit est un script PowerShell conçu pour les équipes **Blue Team**, les administrateurs système et les auditeurs de sécurité. Il permet de collecter rapidement une photographie complète de la configuration d'une machine Windows, d'identifier les écarts par rapport aux bonnes pratiques de sécurité, et de générer un rapport HTML interactif exploitable immédiatement.

Le script ne contient **aucune commande d'écriture, de modification ou d'exploitation**. Il s'appuie exclusivement sur des appels en lecture seule (`Get-*`, `netsh`, `bcdedit`, `wevtutil`, etc.) et ne modifie en aucun cas le système audité.

---

### Dashboard

<a href="https://raw.githubusercontent.com/Anadema/PowerAudit/refs/heads/main/Image/Dashboard_fr.jpg">
  <img src="https://raw.githubusercontent.com/Anadema/PowerAudit/refs/heads/main/Image/Dashboard_fr.jpg" 
       alt="Image" 
       width="800">
</a>

### Matrice Mitre

<a href="https://raw.githubusercontent.com/Anadema/PowerAudit/refs/heads/main/Image/Mitre_fr.jpg">
  <img src="https://raw.githubusercontent.com/Anadema/PowerAudit/refs/heads/main/Image/Mitre_fr.jpg" 
       alt="Image" 
       width="800">
</a>

### Remédiation

<a href="https://raw.githubusercontent.com/Anadema/PowerAudit/refs/heads/main/Image/Remediation_fr.jpg">
  <img src="https://raw.githubusercontent.com/Anadema/PowerAudit/refs/heads/main/Image/Remediation_fr.jpg" 
       alt="Image" 
       width="800">
</a>

## Avertissement légal

> L'auteur de ce script **ne peut être tenu responsable** de l'usage qui en est fait.  
> PowerAudit est conçu pour être utilisé **uniquement sur des systèmes dont vous êtes propriétaire ou pour lesquels vous disposez d'une autorisation écrite explicite**.  
> Toute utilisation sur un système tiers sans autorisation est illégale et contraire à l'éthique.  
> Ce script ne contient que des commandes de **lecture** et ne modifie, n'exfiltre ni n'altère aucune donnée du système.

---

## Prérequis

### PowerShell et droits administrateur

Le script nécessite des **droits Administrateur** pour accéder à certaines informations système (journaux de sécurité, politique de sécurité locale, GPO, etc.).

Il existe deux façons de l'exécuter :

**Option 1 — Modifier la politique d'exécution (recommandé, persistant)**

Ouvrir PowerShell en tant qu'Administrateur et exécuter :
```powershell
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine
```
Puis lancer le script normalement :
```powershell
powershell.exe -File ".\PowerAudit_3_1.ps1"
```

**Option 2 — Bypass ponctuel (sans modification système)**
```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\PowerAudit_3_1.ps1"
```

> Dans les deux cas, PowerShell doit être lancé **en tant qu'Administrateur** (clic droit → Exécuter en tant qu'administrateur).

### Version minimale

- Windows 10 / Windows Server 2016 ou supérieur
- PowerShell 5.0 minimum

---

## Lancement

```powershell
powershell.exe -ExecutionPolicy Bypass -File ".\PowerAudit_3_1.ps1"
```

---

## Menus

### Menu 1 — Audit complet

Lance l'ensemble des 46 modules d'audit en séquence et génère un rapport HTML interactif complet.

Le rapport est enregistré dans le répertoire courant sous la forme :
```
pwaudit_NOMACHINE_rapport_complet_AAAA-MM-JJ_HH-mm.html
```

### Menu 2 — Audit sélectif

Permet de choisir manuellement les modules à exécuter via un menu interactif avec cases à cocher.

| Commande | Action |
|----------|--------|
| `[numéro]` | Cocher / décocher un module |
| `A` | Tout sélectionner |
| `N` | Tout décocher |
| `V` | Valider et générer le rapport |
| `Q` | Retour sans générer |

Le rapport partiel est enregistré sous la forme :
```
pwaudit_NOMACHINE_rapport_partiel_AAAA-MM-JJ_HH-mm.html
```

### Menu 3 — Exécution individuelle

Permet d'exécuter un module unique et d'en afficher le résultat directement dans le shell, sans génération de rapport HTML. Utile pour une vérification rapide ou un diagnostic ciblé.

### Menu 4 — Ouvrir le dernier rapport

Ouvre dans le navigateur par défaut le dernier rapport HTML généré durant la session courante.

### Menu 5 — Résumé rapide de la machine

Affiche dans la console un récapitulatif complet de la machine :
- Informations système (OS, build, CPU, RAM, BIOS, uptime)
- Disques avec barre de remplissage et code couleur
- Comptes locaux avec rôles (actif / inactif / admin)
- **Clé de licence Windows** (décodage OEM + registre)
- **Mots de passe des réseaux Wi-Fi sauvegardés**
- Chemin et date du dernier rapport généré

---

## Modules d'audit (46)

| # | Identifiant | Description | Catégorie |
|---|-------------|-------------|-----------|
| 01 | `BCD` | Gestionnaire de démarrage | Système |
| 02 | `OS` | Informations OS | Système |
| 03 | `ENV` | Variables d'environnement | Système |
| 04 | `PROC-TREE` | Arbre des processus | Processus |
| 05 | `PROC-LIST` | Liste des processus | Processus |
| 06 | `EXEC-POL` | Politique PowerShell | Sécurité |
| 07 | `SECEDIT` | Politique de sécurité locale | Sécurité |
| 08 | `USERS` | Comptes locaux | Comptes |
| 09 | `GROUPS` | Groupes locaux | Comptes |
| 10 | `SHARES` | Partages réseau (SMB) | Réseau |
| 11 | `USB` | Historique USB | Système |
| 12 | `DISK` | Partitions / Disques | Système |
| 13 | `IPCONFIG` | Configuration réseau | Réseau |
| 14 | `NETSTAT` | Connexions réseau actives | Réseau |
| 15 | `ROUTE` | Table de routage | Réseau |
| 16 | `WSUS` | Source mises à jour (WSUS) | MAJ |
| 17 | `HOTFIX` | Mises à jour installées | MAJ |
| 18 | `NTP` | Source de temps (NTP) | Réseau |
| 19 | `WIFI` | Configuration Wi-Fi | Réseau |
| 20 | `DNS-CACHE` | Cache DNS | Réseau |
| 21 | `PROXY` | Configuration Proxy | Réseau |
| 22 | `ARP` | Table ARP | Réseau |
| 23 | `HOSTS` | Fichier HOSTS | Réseau |
| 24 | `SERVICES` | État des services Windows | Services |
| 25 | `FW-STATE` | Pare-feu — état | Pare-feu |
| 26 | `FW-IN` | Pare-feu — règles entrantes | Pare-feu |
| 27 | `FW-OUT` | Pare-feu — règles sortantes | Pare-feu |
| 28 | `AV` | Antivirus | Sécurité |
| 29 | `TASKS` | Tâches planifiées | Persistance |
| 30 | `APPS` | Logiciels installés | Système |
| 31 | `EVT-SYS` | Journal Système (50 derniers) | Journaux |
| 32 | `EVT-APP` | Journal Application (50 derniers) | Journaux |
| 33 | `GPO` | GPO / GPResult | Sécurité |
| 34 | `STARTUP` | Programmes au démarrage | Persistance |
| 35 | `IPv6` | IPv6 — Adresses et Privacy | Réseau |
| 36 | `BITLOCKER` | BitLocker — Chiffrement disque | Chiffrement |
| 37 | `CERTS` | Certificats — Magasin système | Chiffrement |
| 38 | `EVT-SEC` | Journal Sécurité (50 derniers) | Forensique |
| 39 | `RECENT-FILES` | Fichiers récemment modifiés (72h) | Forensique |
| 40 | `RDP-HIST` | Connexions RDP récentes | Forensique |
| 41 | `PS-HIST` | Activité PowerShell (historique) | Forensique |
| 42 | `UAC` | Droits UAC et privilèges | Vulnérabilités |
| 43 | `APPLOCKER` | AppLocker / SRP | Vulnérabilités |
| 44 | `LSAPROT` | Credential Guard / LSA Protection | Vulnérabilités |
| 45 | `NET-GEO` | Connexions réseau établies — GeoIP | Vulnérabilités |
| 46 | `PS-MODULES` | Modules PowerShell chargés | Vulnérabilités |

---

## Rapport HTML

Le rapport généré est un fichier HTML autonome (sans dépendance externe) qui contient :

- **Tableau de bord** avec score de sécurité global, jauges par domaine et indicateurs clés
- **Matrice MITRE ATT&CK** — les techniques détectées sont mises en évidence avec leur niveau de risque ; cliquer sur une technique ouvre la fiche officielle sur attack.mitre.org
- **Plan de remédiation** priorisé par niveau de criticité
- **Détail de chaque module** avec résultat brut et conseils de sécurité
- **Navigation** latérale avec recherche et filtres
- **Références** de sécurité (ANSSI, MITRE, CIS, etc.)

### Calcul du score de sécurité

Le score n'est **pas une moyenne**. Il s'inspire de la formule **CVSS** adaptée au contexte défensif :

```
Risque(domaine) = Impact x Exploitabilite
  Impact         = poids_domaine / 4        (normalise 0.25 -> 1.0)
  Exploitabilite = (10 - score_domaine) / 10

Score brut = 10 - (risque_moyen x 10)
```

**Plafonds punitifs** — certains domaines critiques en échec bloquent le score global, indépendamment des autres modules :

| Condition | Plafond | Signification |
|-----------|---------|---------------|
| Domaine critique (poids >= 4) a <= 2/10 | **3.9** | Ex : Antivirus désactivé -> Critique certain |
| Domaine critique (poids >= 4) a <= 4/10 | **4.9** | Echec sévère sur domaine vital |
| Domaine critique (poids >= 4) a <= 6/10 | **6.4** | Défaillance partielle sur domaine vital |
| Domaine important (poids >= 3) a <= 2/10 | **4.9** | Echec majeur |
| Domaine important (poids >= 3) a <= 4/10 | **5.9** | Défaillance importante |

Les domaines critiques (poids 4) sont : Antivirus, Pare-feu, Mises à jour, Journal Sécurité, LSA Protection.

**Malus de couverture** — un audit partiel tire le score vers 5/10 pour refléter l'incertitude.

**Seuils d'affichage** :

| Score | Label | Couleur |
|-------|-------|---------|
| 0 – 4.9 | Critique | Rouge |
| 5 – 6.9 | Attention | Jaune |
| 7 – 10 | Bon | Vert |

---

## Licence

Apache 2.0 — voir fichier `LICENSE`.

---

## Auteurs

Anadema
