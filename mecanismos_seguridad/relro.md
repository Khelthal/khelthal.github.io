---
layout: default
title: Relocation Read-Only
parent: Mecanismos de Seguridad
nav_order: 3
---

# Relocation Read-Only (RELRO)
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

Este mecanismo de seguridad está enfocado a mitigar ataques contra la 
[Global Offset Table](../../conceptos/got.html){: .label .label-green }.
Este mecanismo ofrece 2 niveles.

---

Partial RELRO
{: .label .label-purple }

En este modo, lo único que sucede es que la sección GOT del programa
es colocada antes de las secciones donde se guardan variables globales,
por lo que se elimina la posibilidad de modificar la global offset
table mediante overflow.

---

Full RELRO
{: .label .label-purple }

Hace que la sección GOT sea de solo lectura, por lo que mitiga ataques
que depeden de escribir en esta sección.

---

## Mitiga

Este mecanismo mitiga los siguientes tipos de errores y tipos de explotación:

[Format String Bug](../../tipos_errores/espacial/format_string.html){: .btn .btn-green } (Mitigada
parcialmente con Full RELRO)

Por lo que probablemente sea mejor intentar otras técnicas contra binarios
que tengan esta protección activada.