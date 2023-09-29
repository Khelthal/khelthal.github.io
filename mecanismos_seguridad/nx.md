---
layout: default
title: No eXecute
parent: Mecanismos de Seguridad
nav_order: 5
---

# No eXecute (NX)
{: .no_toc }

## Table of contents
{: .no_toc .text-delta }

1. TOC
{:toc}

---

## Información General

Esta protección consiste en marcar algunas áreas del programa (como el stack)
como no ejecutables. Esta protección mitiga técnicas de inyección de código,
ya que sin permisos de ejecución, el código inyectado no puede ejecutarse.

---

## Mitiga

Este mecanismo mitiga los siguientes tipos de errores y tipos de explotación:

[Code Injection](../../tipos_explotacion/control/code_injection.html){: .btn .btn-green }

Por lo que probablemente sea mejor intentar otras técnicas contra binarios
que tengan esta protección activada.