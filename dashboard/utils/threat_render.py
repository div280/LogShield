"""
threat_render.py
SIEM-style Threat Overview panel rendering via Plotly.
Knowledge graph uses Plotly (already in requirements.txt) for
reliable Streamlit embedding without extra JS dependencies.
"""
import streamlit as st
import plotly.graph_objects as go


def _plotly_base(t, height=300):
    return dict(
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        font=dict(
            family='Inter, sans-serif',
            color=t['txt2'],
            size=11),
        margin=dict(l=8, r=8, t=8, b=8),
        height=height,
    )


def _card_open(title, t):
    st.markdown(
        f'<div class="siem-card" style="'
        f'background:{t["surface"]};'
        f'border:1px solid {t["border"]};'
        f'border-radius:10px;'
        f'box-shadow:0 10px 28px rgba(0,0,0,0.22);'
        f'margin-bottom:12px;overflow:hidden">'
        f'<div style="padding:13px 18px;'
        f'border-bottom:1px solid {t["border"]};'
        f'border-left:4px solid {t["accent"]}">'
        f'<div style="font-size:11px;font-weight:800;'
        f'letter-spacing:2.5px;color:{t["txt3"]};'
        f'text-transform:uppercase">{title}</div>'
        f'</div><div style="padding:14px 16px 8px 16px">',
        unsafe_allow_html=True)


def _card_close():
    st.markdown('</div></div>', unsafe_allow_html=True)


def _category_colors(labels, t):
    cmap = {
        'Normal': t['success'],
        'Gap Attack': t['warn'],
        'Shuffle Attack': t['cyan'],
        'Injection Attack': t['accent'],
        'Critical Event': t['accent'],
    }
    return [cmap.get(l, t['txt2']) for l in labels]


def render_threat_map(map_data, t, height=340):
    """Origin vs Impacted activity map (no fake geography)."""
    _card_open('Threat Activity Map', t)
    nodes = map_data.get('nodes', [])
    if not nodes:
        st.caption('No host or account data available.')
        _card_close()
        return

    fig = go.Figure()
    fig.add_shape(
        type='rect', x0=0, y0=0, x1=1, y1=1,
        xref='paper', yref='paper',
        fillcolor=t['bg'], line=dict(width=0))
    fig.add_shape(
        type='line', x0=0.5, y0=0, x1=0.5, y1=1,
        xref='paper', yref='paper',
        line=dict(color=t['border'], width=1, dash='dot'))

    for node_type, color, symbol in [
            ('Origin', t['cyan'], 'circle'),
            ('Impacted', t['accent'], 'diamond')]:
        subset = [n for n in nodes if n['node_type'] == node_type]
        if not subset:
            continue
        fig.add_trace(go.Scatter(
            x=[n['x'] for n in subset],
            y=[n['y'] for n in subset],
            mode='markers+text',
            name=node_type,
            text=[n['label'] for n in subset],
            textposition='top center',
            textfont=dict(size=10, color=t['txt1']),
            marker=dict(
                size=[n['size'] for n in subset],
                color=color,
                symbol=symbol,
                opacity=0.95,
                line=dict(width=2, color=t['txt1'])),
            customdata=[[n['detail'], n['volume']] for n in subset],
            hovertemplate=(
                '<b>%{text}</b><br>'
                'Type: ' + node_type + '<br>'
                'Events: %{customdata[1]:,}<br>'
                '%{customdata[0]}<extra></extra>')))

    fig.update_layout(
        **_plotly_base(t, height),
        xaxis=dict(visible=False, range=[0, 1], fixedrange=True),
        yaxis=dict(visible=False, range=[0, 1], fixedrange=True),
        showlegend=True,
        legend=dict(
            orientation='h', y=1.08, x=0,
            bgcolor='rgba(0,0,0,0)', font=dict(size=10)),
        annotations=[
            dict(x=0.12, y=-0.06, xref='paper', yref='paper',
                 text='ORIGIN', showarrow=False,
                 font=dict(size=10, color=t['cyan'],
                           family='Inter')),
            dict(x=0.88, y=-0.06, xref='paper', yref='paper',
                 text='IMPACTED HOST', showarrow=False,
                 font=dict(size=10, color=t['accent'],
                           family='Inter')),
        ])

    st.plotly_chart(
        fig, use_container_width=True,
        config={'displayModeBar': False})
    st.caption(
        'Node size reflects flagged event volume. '
        'No geographic coordinates are shown when IP '
        'data is unavailable.')
    _card_close()


def render_classification(class_data, t, height=340):
    """Donut chart with ranked category list."""
    _card_open('Log Classification', t)
    labels = class_data.get('labels', [])
    values = class_data.get('values', [])
    ranked = class_data.get('ranked', [])

    if not labels:
        st.caption('No classification data available.')
        _card_close()
        return

    col_d, col_l = st.columns([1.15, 0.85])
    with col_d:
        fig = go.Figure(go.Pie(
            labels=labels,
            values=values,
            hole=0.58,
            marker=dict(
                colors=_category_colors(labels, t),
                line=dict(color=t['surface'], width=2)),
            textinfo='none',
            hovertemplate=(
                '%{label}<br>%{value:,} events<br>'
                '%{percent}<extra></extra>')))
        fig.update_layout(
            **_plotly_base(t, height - 40),
            showlegend=False)
        st.plotly_chart(
            fig, use_container_width=True,
            config={'displayModeBar': False})

    with col_l:
        st.markdown(
            f'<div style="font-size:10px;font-weight:700;'
            f'letter-spacing:1.5px;color:{t["txt3"]};'
            f'text-transform:uppercase;margin-bottom:10px">'
            f'Ranked Categories</div>',
            unsafe_allow_html=True)
        for i, row in enumerate(ranked[:6], 1):
            bar_w = min(row['pct'] * 2.2, 100)
            color = _category_colors([row['label']], t)[0]
            st.markdown(
                f'<div style="margin-bottom:12px">'
                f'<div style="display:flex;'
                f'justify-content:space-between;'
                f'font-size:12px;color:{t["txt1"]};'
                f'margin-bottom:4px">'
                f'<span>{i}. {row["label"]}</span>'
                f'<span style="font-family:JetBrains Mono,'
                f'monospace;color:{t["txt2"]}">'
                f'{row["count"]:,}</span></div>'
                f'<div style="background:{t["border"]};'
                f'border-radius:3px;height:6px">'
                f'<div style="width:{bar_w}%;background:'
                f'{color};height:6px;border-radius:3px">'
                f'</div></div></div>',
                unsafe_allow_html=True)
    _card_close()


def render_processing_rate(rate_data, t, height=260):
    """Large bold gauge with monospace center readout."""
    _card_open('Log Processing Rate', t)
    rate = rate_data.get('rate', 0)
    max_val = rate_data.get('max_val', 1000)

    fig = go.Figure(go.Indicator(
        mode='gauge+number',
        value=rate,
        number=dict(
            font=dict(
                family='JetBrains Mono, monospace',
                size=52,
                color=t['txt1'],
                weight=700),
            valueformat=',d'),
        title=dict(
            text=rate_data.get('rate_label', 'events/min'),
            font=dict(size=13, color=t['txt2'])),
        gauge=dict(
            axis=dict(
                range=[0, max_val],
                tickwidth=1,
                tickcolor=t['border'],
                tickfont=dict(
                    family='JetBrains Mono, monospace',
                    size=10, color=t['txt3'])),
            bar=dict(color=t['accent'], thickness=0.28),
            bgcolor=t['bg'],
            borderwidth=0,
            steps=[
                dict(range=[0, max_val * 0.45],
                     color='rgba(0,200,83,0.10)'),
                dict(range=[max_val * 0.45, max_val * 0.75],
                     color='rgba(255,179,0,0.12)'),
                dict(range=[max_val * 0.75, max_val],
                     color='rgba(232,52,58,0.14)'),
            ],
            threshold=dict(
                line=dict(color=t['warn'], width=4),
                thickness=0.85,
                value=rate)),
    ))
    fig.update_layout(**_plotly_base(t, height))
    st.plotly_chart(
        fig, use_container_width=True,
        config={'displayModeBar': False})
    st.markdown(
        f'<div style="display:flex;'
        f'justify-content:space-between;'
        f'font-size:11px;color:{t["txt2"]};'
        f'font-family:JetBrains Mono,monospace;'
        f'margin-top:-6px">'
        f'<span>{rate_data.get("min_label", "0")}</span>'
        f'<span>{rate_data.get("max_label", "1000")}</span>'
        f'</div>',
        unsafe_allow_html=True)
    _card_close()


def render_trend_chart(trend_data, t, height=320):
    """Multi-line trend with right-side legend labels."""
    _card_open('Log, Event, and Alarm Trend', t)
    times = trend_data.get('times', [])
    if not times:
        st.caption('No trend data available.')
        _card_close()
        return

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=times, y=trend_data.get('logs', []),
        mode='lines', name='Logs Processed',
        line=dict(color=t['cyan'], width=2.5),
        hovertemplate=(
            'Time: %{x}<br>'
            'Logs processed in this interval: %{y:,}<br>'
            'Total log records parsed from the upload'
            '<extra>Logs</extra>')))
    fig.add_trace(go.Scatter(
        x=times, y=trend_data.get('events', []),
        mode='lines', name='Events',
        line=dict(color=t['txt2'], width=2, dash='dot'),
        hovertemplate=(
            'Time: %{x}<br>'
            'Security events in this interval: %{y:,}<br>'
            'Windows Security channel events recorded'
            '<extra>Events</extra>')))
    fig.add_trace(go.Scatter(
        x=times, y=trend_data.get('alarms', []),
        mode='lines', name='Anomalies and Alarms',
        line=dict(color=t['accent'], width=2.5),
        hovertemplate=(
            'Time: %{x}<br>'
            'Anomalies and alarms: %{y:,}<br>'
            'AI-flagged outliers plus critical Event IDs'
            '<extra>Alarms</extra>')))

    fig.update_layout(
        **_plotly_base(t, height),
        xaxis=dict(
            gridcolor=t['border'], linecolor=t['border'],
            tickfont=dict(size=9)),
        yaxis=dict(
            gridcolor=t['border'], linecolor=t['border'],
            tickfont=dict(
                family='JetBrains Mono, monospace', size=9)),
        legend=dict(
            orientation='v',
            yanchor='top', y=1,
            xanchor='left', x=1.02,
            bgcolor='rgba(0,0,0,0)',
            bordercolor=t['border'],
            borderwidth=1,
            font=dict(size=11, color=t['txt1'])))

    st.plotly_chart(
        fig, use_container_width=True,
        config={'displayModeBar': False})
    _card_close()


def render_knowledge_graph(graph_data, t, height=400):
    """Left-to-right attack narrative with bold nodes and edges."""
    _card_open('Knowledge Graph', t)
    nodes = graph_data.get('nodes', [])
    edges = graph_data.get('edges', [])
    if not nodes:
        st.caption('Insufficient data for attack narrative.')
        _card_close()
        return

    kind_style = {
        'account': (t['cyan'], 'circle', 28),
        'session': (t['txt2'], 'square', 22),
        'process': (t['warn'], 'diamond', 26),
        'event': (t['accent'], 'hexagon', 30),
        'verdict': (t['accent'], 'star', 34),
    }

    id_to_xy = {n['id']: (n['x'], n['y']) for n in nodes}
    fig = go.Figure()

    for edge in edges:
        x0, y0 = id_to_xy.get(edge['from'], (0, 0.5))
        x1, y1 = id_to_xy.get(edge['to'], (1, 0.5))
        fig.add_trace(go.Scatter(
            x=[x0, x1], y=[y0, y1],
            mode='lines',
            line=dict(color=t['accent'], width=4),
            hoverinfo='skip',
            showlegend=False,
            opacity=0.85))

    for n in nodes:
        kind = n['node_kind']
        color, symbol, size = kind_style.get(
            kind, (t['txt2'], 'circle', 24))
        line_color = t['txt1'] if kind == 'verdict' else t['border']
        line_width = 3 if kind == 'verdict' else 1.5
        fig.add_trace(go.Scatter(
            x=[n['x']], y=[n['y']],
            mode='markers+text',
            text=[n['label']],
            textposition='bottom center',
            textfont=dict(
                size=11, color=t['txt1'],
                family='Inter, sans-serif'),
            marker=dict(
                size=size, color=color, symbol=symbol,
                line=dict(width=line_width, color=line_color),
                opacity=0.98),
            customdata=[[
                n['title'], n['timestamp'], n['detail']]],
            hovertemplate=(
                '<b>%{customdata[0]}</b><br>'
                'Type: %{text}<br>'
                'Time: %{customdata[1]}<br>'
                '%{customdata[2]}<extra></extra>'),
            showlegend=False))

    for n in nodes:
        fig.add_annotation(
            x=n['x'], y=n['y'] + 0.12,
            text=n['title'][:42],
            showarrow=False,
            font=dict(size=9, color=t['txt2'],
                      family='Inter, sans-serif'),
            align='center')

    fig.update_layout(
        **_plotly_base(t, height),
        xaxis=dict(visible=False, range=[-0.05, 1.05],
                   fixedrange=True),
        yaxis=dict(visible=False, range=[0.1, 0.9],
                   fixedrange=True))

    st.plotly_chart(
        fig, use_container_width=True,
        config={'displayModeBar': False})
    st.caption(
        'Follow the narrative from account activity through '
        'process execution to critical events and the final '
        'integrity verdict. Hover each node for details.')
    _card_close()


def render_flagged_events_table(flagged_df, t):
    """Sortable table of flagged events for forensic drill-down."""
    _card_open('Flagged and Critical Events', t)
    if flagged_df is None or len(flagged_df) == 0:
        st.caption('No flagged events in the current analysis.')
        _card_close()
        return

    st.caption(
        'Sort by any column to inspect individual records. '
        'Reason reflects the LogShield attack category assigned '
        'by the Isolation Forest layer.')
    st.dataframe(
        flagged_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            'timestamp': st.column_config.TextColumn(
                'Timestamp',
                help='When this event was recorded in the log'),
            'event_id': st.column_config.NumberColumn(
                'Event ID',
                help='Windows Security Event ID number'),
            'account': st.column_config.TextColumn(
                'Account',
                help='User or service account associated with the event'),
            'reason_flagged': st.column_config.TextColumn(
                'Reason Flagged',
                help=(
                    'LogShield category: Gap, Shuffle, Injection, '
                    'or Critical Event')),
        })
    _card_close()


def render_threat_overview(panels, tokens):
    """
    Dense SIEM command-center grid layout.

    Time Complexity: O(n)
    Space Complexity: O(n)
    """
    t = tokens
    t['bg'] = tokens.get('bg', tokens['surface'])

    row1_left, row1_right = st.columns([1.55, 1], gap='small')
    with row1_left:
        render_threat_map(
            panels.get('threat_map', {}), t, height=360)
    with row1_right:
        render_classification(
            panels.get('classification', {}), t, height=360)

    row2_left, row2_right = st.columns([1, 1.55], gap='small')
    with row2_left:
        render_processing_rate(
            panels.get('processing_rate', {}), t, height=280)
    with row2_right:
        render_trend_chart(
            panels.get('trend', {}), t, height=280)

    render_knowledge_graph(
        panels.get('knowledge_graph', {}), t, height=420)
