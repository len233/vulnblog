# Rapport d'Audit de Sécurité - VulnBlog

**Date**: 18 décembre 2025  
**Application**: VulnBlog - Application Symfony intentionnellement vulnérable  
**Framework**: Symfony 6.x avec PHP  

## Résumé Exécutif

Cette application Symfony contient de **nombreuses vulnérabilités critiques** délibérément introduites à des fins de formation en sécurité. L'audit a révélé **14 vulnérabilités majeures** réparties dans plusieurs catégories OWASP Top 10.

### Niveau de Risque Global: **CRITIQUE** ⚠️

---

## Vulnérabilités Identifiées

### 🔴 **CRITIQUE - Injection SQL**

#### 1. SQL Injection dans UserRepository::getUserLogin() 
**Fichier**: `src/Repository/UserRepository.php:60`
```php
$rawSql = "SELECT * FROM user WHERE email = '$email' AND password = '$hashedPassword' LIMIT 1";
```
- **Impact**: Bypass d'authentification, extraction de données sensibles
- **Exploitation**: `email=' OR '1'='1' --`

#### 2. SQL Injection dans PostRepository::search()
**Fichier**: `src/Repository/PostRepository.php:52`
```php
$rawSql = "SELECT * FROM post WHERE content LIKE '%" . $query . "%' OR title LIKE '%" . $query . "%' ORDER BY date DESC";
```
- **Impact**: Extraction de toutes les données de la base
- **Exploitation**: `%'; DROP TABLE user; --`

### 🔴 **CRITIQUE - Hachage de Mots de Passe Faible**

#### 3. Utilisation de MD5 pour les Mots de Passe
**Fichiers**: 
- `src/Security/Hasher/Md5Hasher.php`
- `src/Controller/LoginController.php:75`
- `src/Controller/AdminController.php:86`

```php
$user->setPassword(md5($password));
```
- **Impact**: Mots de passe facilement cassables avec rainbow tables
- **Recommandation**: Utiliser bcrypt ou Argon2

### 🔴 **CRITIQUE - Template Injection (SSTI)**

#### 4. Injection de Template Twig
**Fichier**: `src/Twig/TemplateFromStringExtension.php:18`
```php
public function templateFromString($environment, $templateCode)
{
    $template = $environment->createTemplate($templateCode);
    return $template->render();
}
```

**Utilisation dans**: `templates/blog/post.html.twig:31`
```twig
{{ template_from_string(comment.author.aboutMe) }}
```
- **Impact**: Exécution de code arbitraire côté serveur
- **Exploitation**: `{{_self.env.getRuntime('Symfony\\Component\\Process\\Process').run('cat /etc/passwd')}}`

### 🔴 **CRITIQUE - Command Injection**

#### 5. Command Injection dans Analytics::track()
**Fichier**: `src/Services/Analytics.php:24`
```php
$command = 'curl -k -s -o /dev/null -w "%{http_code}" ' . $referer;
$statusCode = shell_exec($command);
```
- **Impact**: Exécution de commandes système arbitraires
- **Exploitation**: Via header `Referer: http://example.com; rm -rf /`

#### 6. Command Injection dans UserController::resizeAvatar()
**Fichier**: `src/Controller/UserController.php:145`
```php
$command = 'convert ' . $avatarFile . ' -resize 200x200 ' . $avatarFile;
shell_exec($command);
```
- **Impact**: Exécution de commandes via nom de fichier malveillant
- **Exploitation**: Nom de fichier contenant `; malicious_command`

### 🔴 **CRITIQUE - Désérialisation Non Sécurisée**

#### 7. Désérialisation de Cookies
**Fichier**: `src/Services/UserPref.php:28`
```php
$data = base64_decode(urldecode($cookie));
return unserialize($data);
```
- **Impact**: Exécution de code arbitraire via payload PHP
- **Exploitation**: Chaîne d'objets malveillants dans cookie `USER_PREF`

### 🔴 **CRITIQUE - Path Traversal**

#### 8. Directory Traversal
**Fichier**: `src/Controller/BlogController.php:64`
```php
$contentPath = __DIR__ . '/../../templates/legal/' . $request->get('p');
if (is_dir($contentPath) || !file_exists($contentPath))
    throw $this->createNotFoundException();
return new Response(file_get_contents($contentPath));
```
- **Impact**: Lecture de fichiers sensibles du système
- **Exploitation**: `?p=../../../../../etc/passwd`

### 🔴 **CRITIQUE - Server-Side Request Forgery (SSRF)**

#### 9. SSRF dans Avatar::getFromUrl()
**Fichier**: `src/Services/Avatar.php:15`
```php
$content = file_get_contents($url);
```
- **Impact**: Scan de réseau interne, accès aux métadonnées cloud
- **Exploitation**: URLs comme `file:///etc/passwd` ou `http://169.254.169.254/`

### 🟠 **ÉLEVÉ - Cross-Site Scripting (XSS)**

#### 10. XSS Stocké dans les Commentaires
**Fichier**: `templates/blog/post.html.twig:34`
```twig
<p>{{ comment.content | raw }}</p>
```
- **Impact**: Exécution de JavaScript malveillant
- **Exploitation**: Commentaire contenant `<script>alert('XSS')</script>`

### 🟠 **ÉLEVÉ - Contrôle d'Accès Défaillant**

#### 11. IDOR dans AdminController::changeRole()
**Fichier**: `src/Controller/AdminController.php:20`
- **Impact**: Modification des rôles d'autres utilisateurs
- **Exploitation**: Manipulation de l'ID utilisateur dans l'URL

#### 12. Mass Assignment dans User::fromArray()
**Fichier**: `src/Entity/User.php:49`
```php
public function fromArray(array $data): void
{
    foreach ($data as $key => $value) {
        $this->$key = $value;
    }
}
```
- **Impact**: Modification de propriétés non autorisées (admin, password)

### 🟡 **MOYEN - Autres Vulnérabilités**

#### 13. Absence de Protection CSRF
- **Impact**: Requêtes forgées (changement de mot de passe, etc.)
- **Localisation**: Tous les formulaires

#### 14. Upload de Fichiers Non Sécurisé
**Fichier**: `src/Controller/UserController.php:71`
- **Impact**: Upload de scripts malveillants
- **Exploitation**: Extensions non filtrées

---

## Recommandations de Correction

### 🔥 **Actions Immédiates (Critique)**

1. **Remplacer toutes les requêtes SQL brutes** par l'ORM Doctrine ou des requêtes préparées
2. **Implémenter bcrypt/Argon2** pour le hachage des mots de passe
3. **Supprimer la fonction template_from_string** ou implémenter un sandbox strict
4. **Échapper tous les paramètres** passés à shell_exec() ou utiliser des alternatives sécurisées
5. **Supprimer unserialize()** et utiliser JSON ou des alternatives sécurisées

### 📋 **Mesures de Sécurité Générales**

1. **Validation et sanitisation** strictes de tous les inputs utilisateur
2. **Implémentation de la protection CSRF** sur tous les formulaires
3. **Filtrage strict des uploads** (whitelist d'extensions, validation MIME)
4. **Principe du moindre privilège** pour les contrôles d'accès
5. **Logging de sécurité** et monitoring des activités suspectes

### 🛡️ **Hardening Infrastructure**

1. **WAF (Web Application Firewall)** pour filtrer les requêtes malveillantes
2. **Isolation réseau** pour limiter l'impact des SSRF
3. **Monitoring de sécurité** en temps réel
4. **Tests de pénétration** réguliers

---

## Conclusion

Cette application présente un **niveau de risque inacceptable** pour un environnement de production. Les vulnérabilités identifiées permettent:

- ✅ **Compromission complète du serveur**
- ✅ **Accès à toutes les données utilisateur**  
- ✅ **Exécution de code arbitraire**
- ✅ **Escalade de privilèges**

**Recommandation**: Cette application ne doit **JAMAIS** être déployée en production sans corrections majeures de sécurité.

---

*Ce rapport a été généré par analyse automatisée du code source. Il est recommandé de compléter par des tests de pénétration manuels.*
