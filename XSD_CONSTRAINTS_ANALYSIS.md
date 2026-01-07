# Analyse des Contraintes XSD Testées

## Contraintes Actuellement Implémentées et Testées ✅

### Facets de Restriction (Simple Types)
- ✅ `minInclusive` - Valeur minimale inclusive
- ✅ `maxInclusive` - Valeur maximale inclusive
- ✅ `minExclusive` - Valeur minimale exclusive
- ✅ `maxExclusive` - Valeur maximale exclusive
- ✅ `minLength` - Longueur minimale de chaîne
- ✅ `maxLength` - Longueur maximale de chaîne
- ✅ `length` - Longueur exacte de chaîne
- ✅ `pattern` - Expression régulière
- ✅ `enumeration` - Liste de valeurs autorisées
- ✅ `totalDigits` - Nombre total de chiffres (décimal)
- ✅ `fractionDigits` - Nombre de chiffres fractionnaires (décimal)
- ✅ `whiteSpace` - Gestion des espaces (preserve, replace, collapse)

### Contraintes d'Occurrence
- ✅ `minOccurs` - Nombre minimum d'occurrences
- ✅ `maxOccurs` - Nombre maximum d'occurrences (exclut unbounded)

### Contraintes Structurelles
- ✅ `sequence` - Ordre des éléments (violation de l'ordre)
- ✅ `choice` - Choix entre éléments
- ✅ `all` - Tous les éléments dans n'importe quel ordre
- ✅ `fixed` - Valeur fixe (ne peut pas être modifiée)
- ✅ `default` - Valeur par défaut
- ✅ `nillable` - Élément peut être nil (xsi:nil="true")

### Contraintes d'Attributs
- ✅ `required` - Attribut requis (use="required")
- ✅ `default` - Valeur par défaut d'attribut

### Contraintes Avancées
- ✅ `abstract` - Type/élément abstrait
- ✅ `mixed` - Contenu mixte (texte + éléments)
- ✅ `union` - Union de types
- ✅ `list` - Liste de types
- ✅ `any` - Élément any (wildcard)
- ✅ `anyAttribute` - Attribut any (wildcard)
- ✅ `xsi:type` - Substitution de type dynamique
- ✅ `substitutionGroup` - Groupe de substitution
- ✅ `unique` - Contrainte d'unicité
- ✅ `key` - Contrainte de clé
- ✅ `keyref` - Référence de clé (clé étrangère)

## Contraintes Parsées mais Peut-être Pas Complètement Testées ⚠️

### Groupes Réutilisables
- ⚠️ `xs:group` - Groupes d'éléments réutilisables (parsé dans `XsdSchema.groups`)
- ⚠️ `xs:attributeGroup` - Groupes d'attributs réutilisables (parsé dans `XsdSchema.attribute_groups`)

## Contraintes XSD Non Implémentées ❌

### XSD 1.1 (Nouvelles Fonctionnalités)
- ❌ `xs:assert` - Assertions personnalisées avec XPath (XSD 1.1)
- ❌ `xs:assertion` - Assertions sur types simples (XSD 1.1)
- ❌ `xs:alternative` - Types conditionnels basés sur XPath (XSD 1.1)
- ❌ `xs:override` - Redéfinition de schémas (XSD 1.1)

### Restrictions sur Attributs
- ❌ `use="prohibited"` - Attribut interdit (ne peut pas être utilisé)
- ❌ `use="optional"` - Déjà géré implicitement mais pas testé explicitement

### Restrictions sur Dérivation
- ❌ `block` - Empêche la dérivation/substitution (block="extension|restriction|substitution")
- ❌ `final` - Empêche la dérivation future (final="extension|restriction|list|union")

### Extension de Types Complexes
- ❌ `xs:extension` - Extension de types complexes (seulement `base_type` parsé, pas la structure d'extension)
- ❌ `xs:restriction` sur types complexes - Restriction de types complexes (seulement sur types simples)

### Composition de Schémas
- ❌ `xs:import` - Importation de schémas externes
- ❌ `xs:include` - Inclusion de schémas
- ❌ `xs:redefine` - Redéfinition de types/groupes (XSD 1.0, déprécié en XSD 1.1)

### Autres
- ❌ `xs:notation` - Notations (rarement utilisé)
- ❌ `form` (elementFormDefault, attributeFormDefault) - Contrôle de qualification namespace (parsé mais pas testé)
- ❌ `targetNamespace` - Namespace cible (parsé et utilisé pour génération XML, mais pas testé pour violations)

## Recommandations

### Priorité Haute
1. **`use="prohibited"`** - Test important pour les attributs interdits
2. **`block` et `final`** - Contraintes importantes sur la dérivation
3. **`xs:group` et `xs:attributeGroup`** - Vérifier que les violations sont bien découvertes pour les groupes

### Priorité Moyenne
4. **`xs:extension`** - Extension de types complexes
5. **`xs:restriction` sur types complexes** - Restriction de types complexes
6. **`form`** - Tester les violations de qualification namespace

### Priorité Basse (XSD 1.1)
7. **`xs:assert`** - Nécessite un parseur XPath
8. **`xs:assertion`** - Nécessite un parseur XPath
9. **`xs:alternative`** - Nécessite un parseur XPath

### Non Prioritaire
10. **`xs:import`, `xs:include`, `xs:redefine`** - Nécessitent la gestion de plusieurs fichiers de schéma
11. **`xs:notation`** - Rarement utilisé

