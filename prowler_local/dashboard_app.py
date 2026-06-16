"""
dashboard/app.py — Local Prowler-like Dash dashboard.
Reads CSV files from ./output/ and displays findings with filters and charts.
Based on Prowler's dashboard structure from github.com/prowler-cloud/prowler
"""
from __future__ import annotations
import glob
import os
import warnings
from datetime import datetime

import dash
import dash_bootstrap_components as dbc
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from dash import Input, Output, callback, dash_table, dcc, html

warnings.filterwarnings("ignore")

# ── Colors (from Prowler config) ──────────────────────────────────────────────
COLORS = {
    "pass":        "#54d283",
    "fail":        "#e67272",
    "warning":     "#fca903",
    "manual":      "#636c78",
    "critical":    "#951649",
    "high":        "#e11d48",
    "medium":      "#ee6f15",
    "low":         "#fcf45d",
    "informational":"#3274d9",
    "bg":          "#1a1a2e",
    "surface":     "#16213e",
    "surface2":    "#0f3460",
    "text":        "#e2e8f0",
}

OUTPUT_DIR = os.environ.get("PROWLER_OUTPUT", os.path.join(os.getcwd(), "output"))

# ── Load CSV data ─────────────────────────────────────────────────────────────
def load_data(folder: str) -> pd.DataFrame:
    files = glob.glob(os.path.join(folder, "*.csv"))
    dfs   = []
    for f in files:
        try:
            df = pd.read_csv(f, sep=";", low_memory=False, dtype={"ACCOUNT_UID": str})
            if len(df) > 0:
                dfs.append(df)
        except Exception:
            pass
    if not dfs:
        return pd.DataFrame(columns=[
            "CHECK_ID","CHECK_TITLE","SERVICE_NAME","STATUS","SEVERITY",
            "ACCOUNT_UID","ACCOUNT_NAME","REGION","STATUS_EXTENDED",
            "RESOURCE_NAME","RESOURCE_UID","REMEDIATION_RECOMMENDATION_TEXT",
            "REMEDIATION_CODE_CLI","TIMESTAMP","CATEGORIES","DESCRIPTION","RISK",
        ])
    df = pd.concat(dfs, ignore_index=True)
    # Normalise severity
    if "SEVERITY" in df.columns:
        df["SEVERITY"] = df["SEVERITY"].str.lower().fillna("informational")
    return df


# ── App ───────────────────────────────────────────────────────────────────────
app = dash.Dash(
    __name__,
    external_stylesheets=[dbc.themes.CYBORG, dbc.icons.BOOTSTRAP],
    title="Prowler Local Dashboard",
    suppress_callback_exceptions=True,
)

# ── Layout helpers ────────────────────────────────────────────────────────────
def kpi_card(title: str, value, color: str, icon: str = "bi-shield"):
    return dbc.Card([
        dbc.CardBody([
            html.Div([
                html.I(className=f"bi {icon} fs-3", style={"color": color}),
                html.Div([
                    html.H2(str(value), className="mb-0 fw-bold", style={"color": color}),
                    html.Small(title, className="text-muted text-uppercase"),
                ], className="ms-3"),
            ], className="d-flex align-items-center"),
        ])
    ], className="mb-3 shadow-sm border-0",
       style={"background": COLORS["surface"], "border": f"1px solid {color}33"})


def make_severity_chart(df: pd.DataFrame) -> go.Figure:
    sev_order = ["critical","high","medium","low","informational"]
    sev_colors = {k: COLORS.get(k,"#888") for k in sev_order}
    fails  = df[df["STATUS"]=="FAIL"] if "STATUS" in df.columns else df
    counts = fails.groupby("SEVERITY").size().reindex(sev_order, fill_value=0)
    fig    = go.Figure(go.Bar(
        x=counts.index.str.capitalize(),
        y=counts.values,
        marker_color=[sev_colors.get(s,"#888") for s in counts.index],
        text=counts.values,
        textposition="outside",
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color=COLORS["text"],
        margin=dict(l=0,r=0,t=10,b=0),
        xaxis=dict(showgrid=False),
        yaxis=dict(showgrid=True, gridcolor="#333"),
        showlegend=False,
        height=250,
    )
    return fig


def make_status_pie(df: pd.DataFrame) -> go.Figure:
    if "STATUS" not in df.columns or df.empty:
        return go.Figure()
    counts = df["STATUS"].value_counts()
    color_map = {
        "PASS":"#54d283","FAIL":"#e67272","WARNING":"#fca903",
        "MANUAL":"#636c78","NOT_APPLICABLE":"#444",
    }
    fig = go.Figure(go.Pie(
        labels=counts.index,
        values=counts.values,
        marker_colors=[color_map.get(s,"#888") for s in counts.index],
        hole=0.55,
        textinfo="percent+label",
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        font_color=COLORS["text"],
        margin=dict(l=0,r=0,t=10,b=0),
        showlegend=True,
        legend=dict(font=dict(color=COLORS["text"])),
        height=250,
    )
    return fig


def make_service_chart(df: pd.DataFrame) -> go.Figure:
    if "SERVICE_NAME" not in df.columns or df.empty:
        return go.Figure()
    fails   = df[df["STATUS"]=="FAIL"] if "STATUS" in df.columns else df
    by_svc  = fails.groupby("SERVICE_NAME").size().sort_values(ascending=True).tail(15)
    fig     = go.Figure(go.Bar(
        x=by_svc.values,
        y=by_svc.index,
        orientation="h",
        marker_color=COLORS["fail"],
        text=by_svc.values,
        textposition="outside",
    ))
    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font_color=COLORS["text"],
        margin=dict(l=0,r=0,t=10,b=50),
        xaxis=dict(showgrid=True, gridcolor="#333"),
        yaxis=dict(showgrid=False),
        height=350,
    )
    return fig


# ── Main layout ───────────────────────────────────────────────────────────────
app.layout = dbc.Container([

    # Header
    dbc.Row([
        dbc.Col([
            html.H2("🔐 Prowler Local Dashboard", className="fw-bold mb-0"),
            html.Small("AWS Security Findings — 100% Local", className="text-muted"),
        ], width=8),
        dbc.Col([
            dbc.Button("↻ Refresh", id="btn-refresh", color="outline-light",
                       size="sm", className="me-2"),
            dbc.Button("📥 Export CSV", id="btn-export", color="outline-success",
                       size="sm"),
            dcc.Download(id="download-csv"),
        ], width=4, className="d-flex justify-content-end align-items-center"),
    ], className="py-3 mb-3 border-bottom border-secondary"),

    # Interval for auto-refresh
    dcc.Interval(id="interval", interval=60*1000, n_intervals=0),

    # KPI row
    dbc.Row(id="kpi-row", className="mb-3"),

    # Charts row
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Status breakdown"),
                dbc.CardBody(dcc.Graph(id="chart-status", config={"displayModeBar":False})),
            ], className="border-0 shadow-sm",
               style={"background": COLORS["surface"]}),
        ], width=4),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Failures by severity"),
                dbc.CardBody(dcc.Graph(id="chart-severity", config={"displayModeBar":False})),
            ], className="border-0 shadow-sm",
               style={"background": COLORS["surface"]}),
        ], width=4),
        dbc.Col([
            dbc.Card([
                dbc.CardHeader("Top failing services"),
                dbc.CardBody(dcc.Graph(id="chart-services", config={"displayModeBar":False})),
            ], className="border-0 shadow-sm",
               style={"background": COLORS["surface"]}),
        ], width=4),
    ], className="mb-3"),

    # Filters
    dbc.Card([
        dbc.CardBody([
            dbc.Row([
                dbc.Col(dcc.Dropdown(id="f-status",    placeholder="Status",
                                    options=["PASS","FAIL","WARNING","MANUAL"],
                                    multi=True, className="dark-select"), width=2),
                dbc.Col(dcc.Dropdown(id="f-severity",  placeholder="Severity",
                                    options=["critical","high","medium","low","informational"],
                                    multi=True, className="dark-select"), width=2),
                dbc.Col(dcc.Dropdown(id="f-service",   placeholder="Service",
                                     multi=True, className="dark-select"), width=2),
                dbc.Col(dcc.Dropdown(id="f-account",   placeholder="Account",
                                     multi=True, className="dark-select"), width=2),
                dbc.Col(dcc.Dropdown(id="f-region",    placeholder="Region",
                                     multi=True, className="dark-select"), width=2),
                dbc.Col(dcc.Input(id="f-search", type="text", placeholder="Search…",
                                  debounce=True,
                                  style={"background":"#222","color":"#eee",
                                         "border":"1px solid #555","width":"100%",
                                         "borderRadius":"4px","padding":"6px"}), width=2),
            ]),
        ])
    ], className="mb-3 border-0 shadow-sm", style={"background": COLORS["surface"]}),

    # Findings table
    dbc.Card([
        dbc.CardHeader(html.Span(id="table-title", children="Findings")),
        dbc.CardBody([
            dash_table.DataTable(
                id="findings-table",
                columns=[
                    {"name": "Check ID",    "id": "CHECK_ID"},
                    {"name": "Title",       "id": "CHECK_TITLE"},
                    {"name": "Account",     "id": "ACCOUNT_NAME"},
                    {"name": "Region",      "id": "REGION"},
                    {"name": "Status",      "id": "STATUS"},
                    {"name": "Severity",    "id": "SEVERITY"},
                    {"name": "Service",     "id": "SERVICE_NAME"},
                    {"name": "Resource",    "id": "RESOURCE_NAME"},
                    {"name": "Details",     "id": "STATUS_EXTENDED"},
                ],
                page_size=25,
                sort_action="native",
                filter_action="none",
                style_table={"overflowX":"auto"},
                style_header={
                    "backgroundColor": COLORS["surface2"],
                    "color": COLORS["text"],
                    "fontWeight": "bold",
                    "border": "1px solid #333",
                },
                style_cell={
                    "backgroundColor": COLORS["surface"],
                    "color": COLORS["text"],
                    "border": "1px solid #333",
                    "textAlign": "left",
                    "padding": "8px",
                    "maxWidth": "300px",
                    "overflow": "hidden",
                    "textOverflow": "ellipsis",
                    "whiteSpace": "nowrap",
                },
                style_data_conditional=[
                    {"if": {"filter_query": '{STATUS} = "FAIL"'},
                     "backgroundColor": "#3a1a1a", "color": "#ff9999"},
                    {"if": {"filter_query": '{STATUS} = "PASS"'},
                     "backgroundColor": "#1a3a1a", "color": "#99ff99"},
                    {"if": {"filter_query": '{STATUS} = "WARNING"'},
                     "backgroundColor": "#3a2a1a", "color": "#ffcc99"},
                    {"if": {"filter_query": '{SEVERITY} = "critical"'},
                     "color": COLORS["critical"], "fontWeight": "bold"},
                    {"if": {"filter_query": '{SEVERITY} = "high"'},
                     "color": COLORS["high"]},
                ],
                tooltip_data=[],
                tooltip_duration=None,
            ),
        ])
    ], className="mb-3 border-0 shadow-sm", style={"background": COLORS["surface"]}),

    # Remediation panel
    dbc.Offcanvas([
        html.Div(id="remediation-content"),
    ], id="remediation-panel", title="Remediation", placement="end", is_open=False,
       style={"width":"480px","background":COLORS["surface"],"color":COLORS["text"]}),

], fluid=True, style={"background": "#0d1117", "minHeight": "100vh", "color": COLORS["text"]})


# ── Callbacks ─────────────────────────────────────────────────────────────────
def get_df():
    return load_data(OUTPUT_DIR)


@app.callback(
    [Output("kpi-row","children"),
     Output("chart-status","figure"),
     Output("chart-severity","figure"),
     Output("chart-services","figure"),
     Output("f-service","options"),
     Output("f-account","options"),
     Output("f-region","options")],
    [Input("interval","n_intervals"), Input("btn-refresh","n_clicks")],
    prevent_initial_call=False,
)
def update_overview(n, _):
    df = get_df()

    if df.empty:
        empty_fig = go.Figure()
        empty_fig.update_layout(paper_bgcolor="rgba(0,0,0,0)",
                                 plot_bgcolor="rgba(0,0,0,0)")
        no_data = [dbc.Col(html.Div("No data found. Run the auditor first.",
                                     className="text-warning"), width=12)]
        return no_data, empty_fig, empty_fig, empty_fig, [], [], []

    total    = len(df)
    fails    = int((df["STATUS"]=="FAIL").sum())     if "STATUS"   in df.columns else 0
    passes   = int((df["STATUS"]=="PASS").sum())     if "STATUS"   in df.columns else 0
    crits    = int(((df["STATUS"]=="FAIL") & (df["SEVERITY"]=="critical")).sum()) if "STATUS" in df.columns else 0
    highs    = int(((df["STATUS"]=="FAIL") & (df["SEVERITY"]=="high")).sum())     if "STATUS" in df.columns else 0

    kpis = dbc.Row([
        dbc.Col(kpi_card("Total Findings",  total,  COLORS["text"],     "bi-list-check"),  width=2),
        dbc.Col(kpi_card("PASS",            passes, COLORS["pass"],     "bi-check-circle"),width=2),
        dbc.Col(kpi_card("FAIL",            fails,  COLORS["fail"],     "bi-x-circle"),    width=2),
        dbc.Col(kpi_card("Critical FAILs",  crits,  COLORS["critical"], "bi-exclamation-triangle-fill"), width=2),
        dbc.Col(kpi_card("High FAILs",      highs,  COLORS["high"],     "bi-exclamation-triangle"), width=2),
        dbc.Col(kpi_card("Accounts",
                         df["ACCOUNT_NAME"].nunique() if "ACCOUNT_NAME" in df.columns else 0,
                         COLORS["informational"], "bi-building"), width=2),
    ]).children

    services = sorted(df["SERVICE_NAME"].dropna().unique().tolist()) if "SERVICE_NAME" in df.columns else []
    accounts = sorted(df["ACCOUNT_NAME"].dropna().unique().tolist()) if "ACCOUNT_NAME" in df.columns else []
    regions  = sorted(df["REGION"].dropna().unique().tolist())       if "REGION"       in df.columns else []

    return (kpis,
            make_status_pie(df),
            make_severity_chart(df),
            make_service_chart(df),
            services, accounts, regions)


@app.callback(
    [Output("findings-table","data"),
     Output("findings-table","tooltip_data"),
     Output("table-title","children")],
    [Input("f-status","value"), Input("f-severity","value"),
     Input("f-service","value"), Input("f-account","value"),
     Input("f-region","value"),  Input("f-search","value"),
     Input("interval","n_intervals")],
    prevent_initial_call=False,
)
def filter_table(statuses, severities, services, accounts, regions, search, _):
    df = get_df()
    if df.empty:
        return [], [], "No data"

    if statuses  and "STATUS"       in df.columns: df = df[df["STATUS"].isin(statuses)]
    if severities and "SEVERITY"    in df.columns: df = df[df["SEVERITY"].isin(severities)]
    if services  and "SERVICE_NAME" in df.columns: df = df[df["SERVICE_NAME"].isin(services)]
    if accounts  and "ACCOUNT_NAME" in df.columns: df = df[df["ACCOUNT_NAME"].isin(accounts)]
    if regions   and "REGION"       in df.columns: df = df[df["REGION"].isin(regions)]
    if search:
        mask = df.apply(lambda r: r.astype(str).str.contains(search, case=False).any(), axis=1)
        df   = df[mask]

    cols    = ["CHECK_ID","CHECK_TITLE","ACCOUNT_NAME","REGION","STATUS",
               "SEVERITY","SERVICE_NAME","RESOURCE_NAME","STATUS_EXTENDED"]
    display = df[[c for c in cols if c in df.columns]].head(500)
    records = display.fillna("").to_dict("records")

    tooltips = [
        {c: {"value": str(row.get("REMEDIATION_RECOMMENDATION_TEXT","")) or
                      str(row.get("STATUS_EXTENDED","")),
             "type": "markdown"}
         for c in cols}
        for row in records
    ]

    title = f"{len(df)} findings"
    return records, tooltips, title


@app.callback(
    Output("download-csv","data"),
    Input("btn-export","n_clicks"),
    prevent_initial_call=True,
)
def export_csv(n):
    df = get_df()
    return dcc.send_data_frame(df.to_csv, "prowler_local_findings.csv",
                                sep=";", index=False)


def run_dashboard(port: int = 8050, debug: bool = False):
    print(f"\n🔐 Prowler Local Dashboard")
    print(f"   Reading from: {OUTPUT_DIR}")
    print(f"   URL: http://localhost:{port}")
    print(f"   Press Ctrl+C to stop\n")
    app.run(debug=debug, port=port, host="127.0.0.1")
