---
layout: default
title: Tools
permalink: /tools/
description: "Open-source security utilities — dependency scanners, triage automation, IOC enrichment."
---

<header class="post-header" style="margin-bottom: 2rem;">
  <div class="post-category">open source</div>
  <h1>Tools</h1>
  <p style="color: var(--text-secondary);">
    Small, focused security utilities released under the MIT license.
    Source lives in the
    <a href="https://github.com/{{ site.author.github | default: 'username' }}/security-research/tree/main/tools"><code>tools/</code></a>
    directory.
  </p>
</header>

{%- assign tool_posts = site.posts | where: "category", "tool-release" -%}

{%- if tool_posts.size > 0 -%}
<div class="card-grid">
  {%- for post in tool_posts -%}
    <div class="card">
      <h3><a href="{{ post.url | relative_url }}">{{ post.title }}</a></h3>
      {%- if post.tagline -%}<p class="card-tagline">{{ post.tagline }}</p>{%- endif -%}
      <div class="card-meta">
        <span>{{ post.date | date: "%Y-%m-%d" }}</span>
        {%- if post.language -%}<span>{{ post.language }}</span>{%- endif -%}
        {%- if post.repo_url -%}<a href="{{ post.repo_url }}" target="_blank" rel="noopener">GitHub ↗</a>{%- endif -%}
      </div>
    </div>
  {%- endfor -%}
</div>
{%- else -%}
<p style="color: var(--text-secondary);">No tools released yet. Check back soon, or browse <a href="https://github.com/{{ site.author.github | default: 'username' }}/security-research/tree/main/tools">the tools directory</a> on GitHub.</p>
{%- endif -%}
