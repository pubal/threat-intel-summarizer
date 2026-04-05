"""HTML template for threat intelligence briefing reports."""

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Threat Intelligence Briefing</title>
<style>
  :root {{
    --bg-primary: #0d1117;
    --bg-secondary: #161b22;
    --bg-tertiary: #21262d;
    --text-primary: #e6edf3;
    --text-secondary: #8b949e;
    --border: #30363d;
    --accent: #58a6ff;
    --critical: #f85149;
    --high: #d29922;
    --awareness: #8b949e;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, sans-serif;
    background: var(--bg-primary);
    color: var(--text-primary);
    line-height: 1.6;
  }}

  header {{
    position: sticky;
    top: 0;
    z-index: 100;
    background: var(--bg-secondary);
    border-bottom: 1px solid var(--border);
    padding: 1rem 2rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 0.5rem;
  }}

  header h1 {{
    font-size: 1.25rem;
    font-weight: 600;
    color: var(--text-primary);
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }}

  header h1::before {{
    content: '\\1F6E1';
  }}

  .header-meta {{
    display: flex;
    gap: 1.5rem;
    font-size: 0.85rem;
    color: var(--text-secondary);
  }}

  .header-meta span {{
    display: flex;
    align-items: center;
    gap: 0.3rem;
  }}

  main {{
    max-width: 960px;
    margin: 2rem auto;
    padding: 0 1.5rem;
  }}

  h2 {{
    font-size: 1.3rem;
    margin: 2rem 0 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 1px solid var(--border);
    color: var(--text-primary);
  }}


  /* Color-coded section dividers — border only, text stays default */
  h2.section-critical {{ border-bottom-color: var(--critical); }}
  h2.section-high {{ border-bottom-color: var(--high); }}

  h3 {{
    font-size: 1.05rem;
    margin: 1.25rem 0 0.5rem;
    color: var(--text-primary);
  }}

  p {{
    margin: 0.5rem 0;
    color: var(--text-secondary);
  }}

  ul, ol {{
    margin: 0.5rem 0 0.5rem 1.5rem;
    color: var(--text-secondary);
  }}

  li {{
    margin: 0.35rem 0;
  }}

  li strong {{
    color: var(--text-primary);
  }}

  a {{
    color: var(--accent);
    text-decoration: none;
  }}

  a:hover {{
    text-decoration: underline;
  }}

  code {{
    background: var(--bg-tertiary);
    padding: 0.15rem 0.4rem;
    border-radius: 4px;
    font-size: 0.9em;
  }}

  blockquote {{
    border-left: 3px solid var(--border);
    padding: 0.5rem 1rem;
    margin: 1rem 0;
    color: var(--text-secondary);
    background: var(--bg-secondary);
    border-radius: 0 6px 6px 0;
  }}

  hr {{
    border: none;
    border-top: 1px solid var(--border);
    margin: 1.5rem 0;
  }}


  .badge-new {{
    display: inline-block;
    padding: 0.1rem 0.45rem;
    background: #17a2b8;
    color: #fff;
    font-size: 0.65rem;
    font-weight: 700;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    border-radius: 3px;
    vertical-align: middle;
    margin-left: 0.4rem;
  }}

  .infocon-badge {{
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-weight: 600;
    font-size: 0.8rem;
    letter-spacing: 0.03em;
  }}
  .infocon-green {{
    background: #238636;
    color: #e6edf3;
  }}
  .infocon-yellow {{
    background: #9e6a03;
    color: #e6edf3;
  }}
  .infocon-orange {{
    background: #bd561d;
    color: #e6edf3;
  }}
  .infocon-red {{
    background: #da3633;
    color: #e6edf3;
  }}

  /* Severity badges in content */
  strong:has(+ em) {{
    font-weight: 600;
  }}

  /* Responsive */
  @media (max-width: 640px) {{
    header {{
      padding: 0.75rem 1rem;
      flex-direction: column;
      align-items: flex-start;
    }}
    .header-meta {{
      flex-direction: column;
      gap: 0.25rem;
    }}
    main {{
      padding: 0 1rem;
    }}
  }}

  .report-footer {{
    max-width: 960px;
    margin: 2rem auto;
    padding: 1rem 1.5rem;
    border-top: 1px solid var(--border);
    font-size: 0.8rem;
    color: var(--text-secondary);
  }}

  /* Print styles */
  @media print {{
    header {{
      position: static;
      background: white;
      color: black;
      border-bottom: 2px solid #333;
    }}
    body {{
      background: white;
      color: black;
    }}
    a {{
      color: #0366d6;
    }}
  }}
</style>
</head>
<body>

<header>
  <h1>Threat Intelligence Briefing</h1>
  <div class="header-meta">
    <span>Generated: {generated}</span>
    <span>Window: {window}</span>
    <span>Items: {item_count}{new_items_suffix}</span>
    {infocon_badge}
  </div>
</header>

<main>
{body}
</main>

{profile_footer}

</body>
</html>
"""
