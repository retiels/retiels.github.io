---
title: (M.IET-CS)  Configuración de Chirpy-Page
date: 2024-10-02 20:15:00 -05:00
categories: [maestría, ciberseguridad, chirpy-page]
tags: [github-page, jekyll]
---

En esta sección, se describe la configuración para tener el blog web basado en Chirpy, además de deployar el proyecto utilizando Github-pages.

## Clonar el Repositorio en Github

1. Logearse con Github
2. Clonar el repositorio de Chirpy-page con Github
3. Nombrar el nuevo repositorio como <username>.github.io, y reemplazar "username", con el nombre de usuario de la cuenta de GitHub.

## Instalar software requerido

1. Instalar Ruby

```bash
    gem -v       # Para verificar la instalación de ruby
```

2. Instalar Jekyll

```bash
    gem install jekyll
    jekyll -v       # Para verificar la instalación de jekyll
```

3. Instalar Bundler

```bash
    gem install bundler
    bundler -v      # Para verificar la instalación de bundler
```

## Clonar el Repositorio en el Host

1. Instalar Git
2. Clonar el repositorio desde el Github personal.
3. Instalar VSCode

Se muestra la siguiente imagen referencial con la estructura de las folder.

![Figura-referencial](/assets/posts/structure.png)

## Preparar la web de Chirpy

- Modificar el archivo "\_config.yaml"
- Guardar los cambios
- Ejecutar con el comando:

```bash
    bundle exec jekyll s
```
