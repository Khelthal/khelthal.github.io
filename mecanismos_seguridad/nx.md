---
layout: default
title: No eXecute
parent: Mecanismos de Seguridad
nav_order: 1
---

# No eXecute
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