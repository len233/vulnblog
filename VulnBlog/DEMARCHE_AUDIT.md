# Démarche d'Audit de Sécurité - VulnBlog

**Auditeur**: GitHub Copilot  
**Date**: 18 décembre 2025  
**Méthodologie**: Analyse statique du code source  

---

## 1. DÉMARCHE D'AUDIT

### 1.1 Méthodologie Adoptée

J'ai suivi une approche systématique d'analyse de code statique (SAST) en examinant chaque composant de l'application Symfony :

1. **Analyse des points d'entrée** (Contrôleurs)
2. **Examination de la logique métier** (Services)
3. **Audit de la couche de données** (Repositories/Entities)
4. **Vérification des templates** (Twig)
5. **Review de la configuration de sécurité**

### 1.2 Outils et Techniques Utilisés

- **Analyse manuelle du code source** - Lecture ligne par ligne des fichiers critiques
- **Recherche de patterns vulnérables** - Identification de fonctions dangereuses
- **Mapping des flux de données** - Suivi des données utilisateur non filtrées
- **Review des configurations** - Vérification des paramètres de sécurité

---

## 2. FAILLES IDENTIFIÉES ET MÉTHODES DE DÉTECTION

### 2.1 🔴 INJECTION SQL

#### Failles Trouvées:
- `UserRepository::getUserLogin()` - Ligne 60
- `PostRepository::search()` - Ligne 52

#### Comment Détectées:
```bash
# Recherche de requêtes SQL brutes
grep -r "SELECT.*\$" src/Repository/
grep -r "rawSql" src/
```

**Indicateurs détectés:**
- Concaténation directe de variables dans requêtes SQL
- Absence d'utilisation de requêtes préparées
- Pattern `"SELECT * FROM table WHERE column = '$variable'"`

#### Code Vulnérable Identifié:
```php
// UserRepository.php:60
$rawSql = "SELECT * FROM user WHERE email = '$email' AND password = '$hashedPassword' LIMIT 1";

// PostRepository.php:52  
$rawSql = "SELECT * FROM post WHERE content LIKE '%" . $query . "%'";
```

---

### 2.2 🔴 HACHAGE FAIBLE (MD5)

#### Comment Détecté:
```bash
# Recherche d'utilisation de MD5
grep -r "md5(" src/
grep -r "Md5Hasher" src/
```

**Fichiers concernés:**
- `src/Security/Hasher/Md5Hasher.php`
- `src/Controller/LoginController.php:75`
- `src/Controller/AdminController.php:86`
- `src/Controller/UserController.php:35`

#### Méthode de Détection:
- Recherche de l'utilisation de `md5()` pour les mots de passe
- Vérification de la configuration du password hasher
- Identification de l'implémentation personnalisée MD5

---

### 2.3 🔴 TEMPLATE INJECTION (SSTI)

#### Comment Détecté:
```bash
# Recherche d'extensions Twig personnalisées
find . -name "*Extension.php" -exec grep -l "createTemplate" {} \;
grep -r "template_from_string" templates/
```

**Chain d'exploitation identifiée:**
1. Extension Twig personnalisée `TemplateFromStringExtension`
2. Fonction `templateFromString()` sans sanitisation
3. Utilisation dans `post.html.twig` avec données utilisateur

#### Code Vulnérable:
```php
// TemplateFromStringExtension.php:18
$template = $environment->createTemplate($templateCode);

// post.html.twig:31
{{ template_from_string(comment.author.aboutMe) }}
```

---

### 2.4 🔴 COMMAND INJECTION

#### Comment Détectées:
```bash
# Recherche de fonctions d'exécution système
grep -r "shell_exec" src/
grep -r "exec(" src/
grep -r "system(" src/
```

**Failles identifiées:**
1. **Analytics::track()** - Injection via header Referer
2. **UserController::resizeAvatar()** - Injection via nom de fichier

#### Analyse du Flow:
```
Referer Header → Analytics::track() → shell_exec("curl ... $referer")
Avatar Upload → resizeAvatar() → shell_exec("convert $file ...")
```

---

### 2.5 🔴 DÉSÉRIALISATION NON SÉCURISÉE

#### Méthode de Détection:
```bash
# Recherche d'unserialize
grep -r "unserialize" src/
grep -r "serialize" src/
```

**Faille dans UserPref.php:**
```php
// UserPref.php:28
$data = base64_decode(urldecode($cookie));
return unserialize($data);
```

#### Flow d'exploitation:
```
Cookie USER_PREF → base64_decode → unserialize → Code Execution
```

---

### 2.6 🔴 PATH TRAVERSAL

#### Comment Détecté:
```bash
# Recherche de file_get_contents avec paramètres utilisateur
grep -r "file_get_contents.*get(" src/
grep -r "__DIR__.*request" src/
```

**Faille dans BlogController.php:**
```php
$contentPath = __DIR__ . '/../../templates/legal/' . $request->get('p');
return new Response(file_get_contents($contentPath));
```

---

### 2.7 🔴 SSRF (Server-Side Request Forgery)

#### Détection:
```bash
# Recherche de requêtes HTTP avec URLs utilisateur
grep -r "file_get_contents.*url" src/
grep -r "curl.*url" src/
```

**Faille dans Avatar.php:**
```php
$content = file_get_contents($url); // $url contrôlé par l'utilisateur
```

---

### 2.8 🟠 CROSS-SITE SCRIPTING (XSS)

#### Méthode de Détection:
```bash
# Recherche de filtres 'raw' dans Twig
grep -r "| raw" templates/
grep -r "is_safe.*html" src/
```

**XSS Stocké identifié:**
```twig
// post.html.twig:34
<p>{{ comment.content | raw }}</p>
```

---

### 2.9 🟠 CONTRÔLE D'ACCÈS DÉFAILLANT

#### IDOR (Insecure Direct Object Reference):
```bash
# Recherche de paramètres d'URL non vérifiés
grep -r "Route.*{.*}" src/Controller/
```

**Mass Assignment:**
```bash
# Recherche de fromArray suspect
grep -r "fromArray" src/
```

---

## 3. CORRECTIFS PROPOSÉS (NON APPLIQUÉS)

### 3.1 🔧 Correction des Injections SQL

#### Méthode Recommandée:
**Remplacement par l'ORM Doctrine:**

```php
// AVANT (Vulnérable)
$rawSql = "SELECT * FROM user WHERE email = '$email' AND password = '$hashedPassword'";

// APRÈS (Sécurisé)
public function getUserLogin(string $email, string $password): ?User
{
    $hashedPassword = $this->passwordHasher->hash($password);
    return $this->findOneBy([
        'email' => $email,
        'password' => $hashedPassword
    ]);
}
```

**Alternative avec requête préparée:**
```php
$stmt = $conn->prepare('SELECT * FROM user WHERE email = ? AND password = ?');
$stmt->execute([$email, $hashedPassword]);
```

### 3.2 🔧 Correction du Hachage de Mot de Passe

#### Configuration Symfony:
```yaml
# config/packages/security.yaml
security:
    password_hashers:
        App\Entity\User:
            algorithm: bcrypt
            cost: 12
```

#### Implémentation:
```php
// Utilisation du service Symfony
public function __construct(
    private PasswordHasherInterface $passwordHasher
) {}

// Hachage sécurisé
$hashedPassword = $this->passwordHasher->hash($plainPassword);
```

### 3.3 🔧 Correction du Template Injection

#### Solution 1 - Suppression complète:
```php
// Supprimer TemplateFromStringExtension.php
// Remplacer dans le template par:
<p>{{ comment.author.aboutMe|escape }}</p>
```

#### Solution 2 - Sandbox strict:
```php
public function templateFromString($environment, $templateCode)
{
    $policy = new SecurityPolicy(
        ['escape'], // tags autorisés
        ['upper', 'lower'], // filtres autorisés
        [], // méthodes autorisées
        [], // propriétés autorisées
        [] // fonctions autorisées
    );
    
    $sandbox = new SandboxExtension($policy);
    $environment->addExtension($sandbox);
    
    $template = $environment->createTemplate($templateCode);
    return $template->render();
}
```

### 3.4 🔧 Correction des Command Injection

#### Analytics Service:
```php
// AVANT
$command = 'curl -k -s -o /dev/null -w "%{http_code}" ' . $referer;

// APRÈS
use Symfony\Component\Process\Process;

public function track(): void
{
    if (!$this->validate($referer)) {
        return;
    }
    
    $process = new Process([
        'curl', '-k', '-s', '-o', '/dev/null', '-w', '%{http_code}', $referer
    ]);
    $process->run();
    $statusCode = $process->getOutput();
}
```

#### Avatar Resize:
```php
// Utilisation de bibliothèque PHP native
use Imagick;

public function resizeAvatar(User $user): Response
{
    $avatarPath = $this->getParameter('avatars_directory') . '/' . $user->getAvatar();
    
    $image = new Imagick($avatarPath);
    $image->resizeImage(200, 200, Imagick::FILTER_LANCZOS, 1);
    $image->writeImage($avatarPath);
    
    return $this->redirectToRoute('app_user');
}
```

### 3.5 🔧 Correction de la Désérialisation

#### Remplacement par JSON:
```php
// UserPref.php - Version sécurisée
class UserPref {
    static public function getFromCookie(): ?UserPref {
        $cookie = $_COOKIE['USER_PREF'] ?? null;
        if (!$cookie) {
            return null;
        }

        $data = json_decode(base64_decode($cookie), true);
        if (!$data || !isset($data['theme'])) {
            return null;
        }
        
        $userPref = new UserPref();
        $userPref->theme = $data['theme'];
        return $userPref;
    }
    
    static public function setCookie(UserPref $userPref): void {
        $data = base64_encode(json_encode(['theme' => $userPref->theme]));
        setcookie('USER_PREF', $data, time() + 3600 * 24 * 365);
    }
}
```

### 3.6 🔧 Correction du Path Traversal

#### Validation stricte du chemin:
```php
public function legalContent(Request $request): Response
{
    $filename = $request->get('p');
    
    // Validation de la liste blanche
    $allowedFiles = ['legal.html', 'terms.html', 'privacy.html'];
    if (!in_array($filename, $allowedFiles)) {
        throw $this->createNotFoundException();
    }
    
    $contentPath = $this->getParameter('legal_directory') . '/' . $filename;
    
    // Vérification du chemin résolv
    $realPath = realpath($contentPath);
    $basePath = realpath($this->getParameter('legal_directory'));
    
    if (!$realPath || strpos($realPath, $basePath) !== 0) {
        throw $this->createNotFoundException();
    }
    
    return new Response(file_get_contents($realPath));
}
```

### 3.7 🔧 Correction du SSRF

#### Validation d'URL stricte:
```php
public function getFromUrl(string $url): string|false
{
    // Validation d'URL
    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return false;
    }
    
    $parsed = parse_url($url);
    
    // Blocklist des schémas dangereux
    $allowedSchemes = ['http', 'https'];
    if (!in_array($parsed['scheme'], $allowedSchemes)) {
        return false;
    }
    
    // Blocklist des IPs privées/localhost
    $ip = gethostbyname($parsed['host']);
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
        return false;
    }
    
    // Utilisation de cURL avec options sécurisées
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    curl_setopt($ch, CURLOPT_MAXREDIRS, 0);
    
    $content = curl_exec($ch);
    curl_close($ch);
    
    return $content;
}
```

### 3.8 🔧 Protection CSRF

#### Activation dans Symfony:
```php
// config/packages/framework.yaml
framework:
    csrf_protection: true
```

#### Utilisation dans les formulaires:
```twig
<form method="post">
    {{ csrf_token('form_name') }}
    <!-- champs du formulaire -->
</form>
```

```php
// Dans le contrôleur
if (!$this->isCsrfTokenValid('form_name', $request->get('_token'))) {
    throw new InvalidCsrfTokenException();
}
```

### 3.9 🔧 Upload Sécurisé

#### Validation stricte des fichiers:
```php
public function uploadAvatar(Request $request, User $user): Response
{
    $avatar = $request->files->get('avatar');
    
    // Validation du type MIME
    $allowedMimes = ['image/jpeg', 'image/png', 'image/gif'];
    if (!in_array($avatar->getMimeType(), $allowedMimes)) {
        throw new BadRequestException('Type de fichier non autorisé');
    }
    
    // Validation de la taille
    if ($avatar->getSize() > 2 * 1024 * 1024) { // 2MB
        throw new BadRequestException('Fichier trop volumineux');
    }
    
    // Génération d'un nom sécurisé
    $filename = uniqid() . '.jpg';
    
    // Déplacement vers répertoire sécurisé
    $avatar->move($this->getParameter('avatars_directory'), $filename);
    
    // Re-encodage de l'image pour éliminer tout code malveillant
    $image = imagecreatefromstring(file_get_contents($targetPath));
    imagejpeg($image, $targetPath, 90);
}
```

---

## 4. PLAN DE REMÉDIATION RECOMMANDÉ

### Phase 1 - Urgences Critiques (Semaine 1)
1. **Désactiver l'extension template_from_string**
2. **Corriger les injections SQL**  
3. **Implémenter bcrypt pour les mots de passe**
4. **Sanitiser les commandes système**

### Phase 2 - Sécurisation (Semaines 2-3)
1. **Implémenter la protection CSRF**
2. **Sécuriser les uploads de fichiers**
3. **Corriger les vulnérabilités SSRF/Path Traversal**
4. **Audit des contrôles d'accès**

### Phase 3 - Hardening (Semaine 4)
1. **Tests de pénétration**
2. **Implémentation du logging de sécurité**
3. **Configuration WAF**
4. **Formation équipe de développement**

---

## 5. CONCLUSION

Cette démarche d'audit a révélé une application intentionnellement vulnérable avec **14 failles critiques**. La méthodologie d'analyse statique systématique a permis d'identifier l'ensemble des vulnérabilités majeures. 

**Les correctifs proposés suivent les bonnes pratiques OWASP** et les standards de sécurité Symfony. L'implémentation de ces corrections nécessiterait environ **4 semaines** avec une équipe expérimentée.

**Note importante**: Cette application étant destinée à la formation, ces vulnérabilités sont volontaires. En environnement réel, un tel niveau de risque nécessiterait un arrêt immédiat du service.
