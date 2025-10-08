import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import glob
import json
import os
from typing import List, Dict, Tuple
import numpy as np
from scipy import stats
import plotly.figure_factory as ff


def load_json_files(file_contents: List[bytes]) -> Dict[str, List[dict]]:
    """Load JSON data from uploaded file contents."""
    data_by_tool = {}
    for file_content in file_contents:
        try:
            data = json.loads(file_content)
            if isinstance(data, list) and data:
                tool_name = data[0].get('toolName', 'Unknown')
                data_by_tool[tool_name] = data
        except json.JSONDecodeError as e:
            st.error(f"Error decoding JSON: {str(e)}")
    return data_by_tool

def extract_metrics(data_by_tool: Dict[str, List[dict]]) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Extract metrics from nested JSON data into separate DataFrames for successful and failed transfers."""
    success_records = []
    failure_records = []
    
    for tool_name, measurements in data_by_tool.items():
        for measurement in measurements:
            # Extract FCP for the entire measurement
            fcp = None
            for test in measurement.get('webTests', []):
                if test.get('fcp'):
                    fcp = test['fcp'] / 1000  # Convert to seconds
                    break  # Stop after finding the first FCP
            
            # Process file transfers
            for transfer in measurement.get('fileTransfers', []):
                record = {
                    'tool_name': tool_name,
                    'measurement_number': measurement['measurementNumber'],
                    'type': 'file_transfer',
                    'filename': transfer['filename'],
                    'file_size': transfer['fileSize'],
                    'content_type': transfer['contentType'],
                    'status_code': transfer['statusCode'],
                    'throughput': transfer['downloadSpeed'] * 8 / 1_000_000,  # Convert to Mbps from bytes per second
                    'dns_lookup': transfer['dnsLookup'] / 1000,  # Convert to seconds
                    'tcp_connection': transfer['tcpConnection'] / 1000,  # Convert to seconds
                    'tls_handshake': transfer['tlsHandshake'] / 1000,  # Convert to seconds
                    'ttfb': transfer['timeToFirstByte'] / 1000,  # Convert to seconds
                    'total_time': transfer['totalTransferTime'] / 1000,  # Convert to seconds
                    'transfer_success': transfer['transferSuccess'],
                    'timestamp': transfer['timestamp'] / 1000,  # Convert to seconds
                    'fcp': fcp  # Assign FCP to each file transfer record
                }
                if transfer['transferSuccess']:
                    success_records.append(record)
                else:
                    failure_records.append(record)
    
    return pd.DataFrame(success_records), pd.DataFrame(failure_records)

def calculate_confidence_interval(data: np.array, confidence=0.95) -> Tuple[float, float]:
    """Calculate confidence interval for the mean."""
    mean = np.mean(data)
    sem = stats.sem(data)
    ci = stats.t.interval(confidence, len(data)-1, loc=mean, scale=sem)
    return ci[0], ci[1]

def deep_dive_analysis(df: pd.DataFrame, tool_name: str, original_df: pd.DataFrame):
    """Perform deep dive analysis for a single tool."""
    st.header(f"Deep Dive Analysis: {tool_name}")
    
    # Measurement run selection
    runs = sorted(df['measurement_number'].unique())
    selected_runs = st.multiselect(
        "Select measurement runs to analyze",
        runs,
        default=runs
    )
    
    filtered_df = df[df['measurement_number'].isin(selected_runs)]
    
    # Metric selection with units
    metrics = {
        'throughput': 'Mbps',
        'ttfb': 's',
        'total_time': 's',
        'dns_lookup': 's',
        'tcp_connection': 's',
        'tls_handshake': 's',
        'fcp': 's'  # Add FCP as a metric
    }
    selected_metric = st.selectbox("Select metric for time series", list(metrics.keys()))
    metric_unit = metrics[selected_metric]
    
    # Log scale toggle
    log_scale = st.checkbox("Use log scale for y-axis")
    
    # Time series analysis with loading spinner
    st.subheader("Time Series Analysis")
    with st.spinner("Generating time series plot..."):
        if selected_metric == 'fcp':
            # Plot FCP without considering file size
            fcp_df = filtered_df.drop_duplicates(subset=['measurement_number'])
            fig = px.line(
                fcp_df,
                x='timestamp',
                y='fcp',
                markers=True,
                title=f"FCP Over Time ({metric_unit})",
                log_y=log_scale,
                labels={'timestamp': 'Time (s)', 'fcp': f"FCP ({metric_unit})"}
            )
        else:
            fig = px.line(
                filtered_df,
                x='timestamp',
                y=selected_metric,
                color='filename' if 'filename' in filtered_df.columns else None,
                markers=True,
                title=f"{selected_metric.replace('_', ' ').title()} Over Time ({metric_unit})",
                log_y=log_scale,
                labels={'timestamp': 'Time (s)', selected_metric: f"{selected_metric.replace('_', ' ').title()} ({metric_unit})"}
            )
        st.plotly_chart(fig)
    
    # Detailed statistics
    st.subheader("Statistical Analysis")
    try:
        stats_df = filtered_df.groupby('measurement_number')[list(metrics.keys())].agg([
            'count', 'mean', 'std', 'min', 'max',
            lambda x: x.quantile(0.25),
            lambda x: x.quantile(0.75)
        ]).round(2)
        
        # Flatten the multi-level column index
        stats_df.columns = ['_'.join(col).strip() for col in stats_df.columns.values]
        
        # Check the number of columns
        num_columns = len(stats_df.columns)
        st.write(f"Number of columns in stats_df: {num_columns}")
        
        # Adjust the renaming to match the number of columns
        new_column_names = []
        for metric in metrics:
            new_column_names.extend([
                f"{metric}_Count", f"{metric}_Mean", f"{metric}_Std", 
                f"{metric}_Min", f"{metric}_Max", f"{metric}_Q1", f"{metric}_Q3"
            ])
        
        stats_df.columns = new_column_names[:num_columns]  # Ensure the list matches the number of columns
        
        st.dataframe(stats_df)
    except Exception as e:
        st.error(f"Error in statistical analysis: {str(e)}")
    
    # Status Code Analysis
    st.subheader("Status Code Analysis")
    
    # Define status code ranges and their colors
    status_colors = {
        200: '#2ecc71',  # Success - Green
        301: '#3498db',  # Redirect - Blue
        302: '#2980b9',  # Redirect - Darker Blue
        400: '#f1c40f',  # Client Error - Yellow
        401: '#e67e22',  # Unauthorized - Orange
        403: '#e74c3c',  # Forbidden - Red
        404: '#c0392b',  # Not Found - Dark Red
        500: '#8e44ad',  # Server Error - Purple
        502: '#9b59b6',  # Bad Gateway - Light Purple
        503: '#2c3e50',  # Service Unavailable - Dark Blue
        504: '#34495e'   # Gateway Timeout - Darker Blue
    }
    
    # Use the original DataFrame for status code analysis
    status_data = original_df.groupby(['measurement_number', 'status_code']).size().reset_index(name='count')
    
    # Create the grid visualization
    fig = go.Figure()
    
    # Add boxes for each status code
    for _, row in status_data.iterrows():
        status = int(row['status_code'])
        measurement = row['measurement_number']
        count = row['count']
        
        # Get color based on status code range
        color = status_colors.get(status, '#95a5a6')  # Default gray for unknown status codes
        
        # Add a box for each occurrence
        fig.add_trace(go.Scatter(
            x=[measurement],
            y=[status],
            mode='markers',
            marker=dict(
                size=20,
                color=color,
                symbol='square',
            ),
            name=f'Status {status}',
            text=f'Status {status} (Count: {count})',
            hoverinfo='text',
            showlegend=True
        ))
    
    # Update layout
    fig.update_layout(
        title='Status Code Distribution by Measurement Run',
        xaxis_title='Measurement Run',
        yaxis_title='Status Code',
        xaxis=dict(
            tickmode='linear',
            tick0=0,
            dtick=1
        ),
        yaxis=dict(
            tickmode='array',
            ticktext=[f'{code}' for code in sorted(status_colors.keys())],
            tickvals=sorted(status_colors.keys())
        ),
        showlegend=True,
        legend_title='Status Codes',
        height=500
    )
    
    st.plotly_chart(fig)
    
    # Add legend explaining status code ranges
    st.write("Status Code Ranges:")
    cols = st.columns(3)
    status_ranges = {
        "2xx - Success": "#2ecc71",
        "3xx - Redirect": "#3498db",
        "4xx - Client Error": "#e67e22",
        "5xx - Server Error": "#8e44ad"
    }
    
    for i, (range_name, color) in enumerate(status_ranges.items()):
        cols[i % 3].markdown(
            f'<div style="background-color: {color}; padding: 10px; border-radius: 5px; color: white;">{range_name}</div>',
            unsafe_allow_html=True
        )
    
    # Measurement Success/Failure Summary
    st.subheader("Measurement Success/Failure Summary")
    success_count = len(df[df['status_code'] == 200])
    failure_count = len(df[df['status_code'] != 200])
    st.write(f"Number of Successful Measurements: {success_count}")
    st.write(f"Number of Failed Measurements: {failure_count}")

def comparison_analysis(df: pd.DataFrame, tools: List[str]):
    """Perform comparison analysis between multiple tools."""
    st.header("Tools Comparison Analysis")
    
    # Filter out failed measurements
    df = df[df['status_code'] == 200]
    
    # Metric selection with units
    metrics = {
        'throughput': 'Mbps',
        'ttfb': 's',
        'total_time': 's',
        'dns_lookup': 's',
        'tcp_connection': 's',
        'tls_handshake': 's'
    }
    selected_metrics = st.multiselect(
        "Select metrics to compare",
        list(metrics.keys()),
        default=['throughput', 'ttfb']
    )
    
    # Content type filter
    if 'content_type' in df.columns:
        content_types = st.multiselect(
            "Select content types",
            df['content_type'].dropna().unique(),
            default=df['content_type'].dropna().unique()
        )
        df = df[df['content_type'].isin(content_types)]
    
    # File filter
    if 'filename' in df.columns:
        filenames = st.multiselect(
            "Select files",
            df['filename'].dropna().unique(),
            default=df['filename'].dropna().unique()
        )
        df = df[df['filename'].isin(filenames)]
    
    # Log scale toggle
    log_scale = st.checkbox("Use log scale for y-axis")
    
    # Create comparison visualizations with loading spinner
    for metric in selected_metrics:
        st.subheader(f"{metric.replace('_', ' ').title()} Comparison")
        metric_unit = metrics[metric]
        
        with st.spinner(f"Generating comparison plot for {metric}..."):
            # Calculate statistics and confidence intervals
            stats_data = []
            for tool in tools:
                tool_data = df[df['tool_name'] == tool][metric].dropna()
                ci_low, ci_high = calculate_confidence_interval(tool_data)
                stats_data.append({
                    'tool': tool,
                    'mean': tool_data.mean(),
                    'ci_low': ci_low,
                    'ci_high': ci_high,
                    'std': tool_data.std()
                })
            
            stats_df = pd.DataFrame(stats_data)
            
            # Create box plot with CI
            fig = go.Figure()
            
            # Add box plots
            for tool in tools:
                tool_data = df[df['tool_name'] == tool][metric].dropna()
                fig.add_trace(go.Box(
                    y=tool_data,
                    name=tool,
                    boxmean='sd'  # Show mean and standard deviation
                ))
            
            # Add confidence intervals
            for _, row in stats_df.iterrows():
                fig.add_trace(go.Scatter(
                    x=[row['tool'], row['tool']],
                    y=[row['ci_low'], row['ci_high']],
                    mode='lines',
                    line=dict(color='red', width=2),
                    showlegend=False
                ))
            
            fig.update_layout(
                title=f"{metric.replace('_', ' ').title()} Distribution by Tool ({metric_unit})",
                yaxis_type='log' if log_scale else 'linear',
                # yaxis=dict(range=[0, None])  # Ensure y-axis starts at 0
            )
            st.plotly_chart(fig)
            
            # Show statistics table
            st.write("Summary Statistics with 95% Confidence Intervals:")
            summary_df = stats_df.round(2)
            summary_df.columns = ['Tool', 'Mean', 'CI Lower', 'CI Upper', 'Std Dev']
            st.dataframe(summary_df)
            
            # Perform t-tests between tools
            # st.write("Statistical Significance (p-values from t-tests):")
            # t_test_results = []
            # for i, tool1 in enumerate(tools):
            #     for tool2 in tools[i+1:]:
            #         t_stat, p_val = stats.ttest_ind(
            #             df[df['tool_name'] == tool1][metric].dropna(),
            #             df[df['tool_name'] == tool2][metric].dropna()
            #         )
            #         t_test_results.append({
            #             'Tool 1': tool1,
            #             'Tool 2': tool2,
            #             'p-value': p_val
            #         })
            # st.dataframe(pd.DataFrame(t_test_results).round(4))

def plot_heatmap(success_df: pd.DataFrame, failure_df: pd.DataFrame):
    """Plot a heatmap showing the distribution of successes and failures."""
    st.subheader("Success and Failure Distribution Heatmap")
    
    # Count successes and failures by tool and measurement number
    success_counts = success_df.groupby(['tool_name', 'measurement_number']).size().reset_index(name='success_count')
    failure_counts = failure_df.groupby(['tool_name', 'measurement_number']).size().reset_index(name='failure_count')
    
    # Merge success and failure counts
    heatmap_data = pd.merge(success_counts, failure_counts, on=['tool_name', 'measurement_number'], how='outer').fillna(0)
    
    # Create a heatmap
    fig = px.density_heatmap(
        heatmap_data,
        x='measurement_number',
        y='tool_name',
        z='success_count',
        color_continuous_scale='Viridis',
        title='Heatmap of Successful Transfers'
    )
    st.plotly_chart(fig)

    # Create a heatmap for failures
    fig = px.density_heatmap(
        heatmap_data,
        x='measurement_number',
        y='tool_name',
        z='failure_count',
        color_continuous_scale='Reds',
        title='Heatmap of Failed Transfers'
    )
    st.plotly_chart(fig)

def categorize_measurements(data_by_tool: Dict[str, List[dict]]) -> pd.DataFrame:
    """Categorize each measurement as full success, full failure, or partial failure."""
    records = []
    
    for tool_name, measurements in data_by_tool.items():
        for measurement in measurements:
            success_count = 0
            failure_count = 0
            
            # Count successes and failures in file transfers
            for transfer in measurement.get('fileTransfers', []):
                if transfer['transferSuccess']:
                    success_count += 1
                else:
                    failure_count += 1
            
            # Count successes and failures in web tests
            for test in measurement.get('webTests', []):
                if test['statusCode'] == 200:
                    success_count += 1
                else:
                    failure_count += 1
            
            # Determine the category
            if success_count > 0 and failure_count == 0:
                category = 'Full Success'
            elif failure_count > 0 and success_count == 0:
                category = 'Full Failure'
            else:
                category = 'Partial Failure'
            
            records.append({
                'tool_name': tool_name,
                'measurement_number': measurement['measurementNumber'],
                'category': category
            })
    
    return pd.DataFrame(records)

def plot_category_heatmap(df: pd.DataFrame):
    """Plot a heatmap showing the distribution of measurement categories."""
    st.subheader("Measurement Success/Failure Heatmap")
    
    # Map categories to numeric values for heatmap
    category_mapping = {'Full Success': 1, 'Partial Failure': 0.5, 'Full Failure': 0}
    df['category_numeric'] = df['category'].map(category_mapping)
    
    # Create a pivot table for the heatmap
    heatmap_data = df.pivot_table(index='tool_name', columns='measurement_number', values='category_numeric', fill_value=0)
    
    # Define a custom color scale
    colorscale = [
        [0.0, 'red'],    # Full Failure
        [0.5, 'yellow'], # Partial Failure
        [1.0, 'green']   # Full Success
    ]
    
    # Create the heatmap with borders
    fig = go.Figure(data=go.Heatmap(
        z=heatmap_data.values,
        x=heatmap_data.columns,
        y=heatmap_data.index,
        colorscale=colorscale,
        colorbar=dict(
            title="Category",
            tickvals=[0, 0.5, 1],
            ticktext=['Full Failure', 'Partial Failure', 'Full Success']
        ),
        showscale=True,
        zmin=0,  # Ensure the color scale starts at 0
        zmax=1,  # Ensure the color scale ends at 1
        xgap=1,  # Gap between x-axis grid lines
        ygap=1   # Gap between y-axis grid lines
    ))
    
    # Ensure all tools are shown on the y-axis
    fig.update_yaxes(type='category', categoryorder='array', categoryarray=heatmap_data.index.tolist())
    
    fig.update_layout(
        xaxis_title='Measurement Number',
        yaxis_title='Tool Name'
    )
    
    st.plotly_chart(fig)

def main():
    st.title("Network Metrics Analyzer")
    
    # File upload
    uploaded_files = st.file_uploader("Upload JSON files", type="json", accept_multiple_files=True)
    
    if not uploaded_files:
        st.info("Please upload one or more JSON files to proceed.")
        return
    
    try:
        # Load JSON data from uploaded files
        file_contents = [uploaded_file.read() for uploaded_file in uploaded_files]
        data_by_tool = load_json_files(file_contents)
        
        if not data_by_tool:
            st.error("No valid JSON data found in the uploaded files.")
            return
        
        # Extract metrics to get the full DataFrame with timestamps
        success_df, failure_df = extract_metrics(data_by_tool)
        
        # Mode selection
        mode = st.sidebar.radio("Select Analysis Mode", ["Deep Dive", "Comparison", "Heatmap"])
        
        if mode == "Deep Dive":
            # Tool selection for deep dive
            selected_tool = st.sidebar.selectbox(
                "Select tool for deep dive analysis",
                success_df['tool_name'].unique()
            )
            # Pass the correct DataFrame with all necessary columns
            deep_dive_analysis(success_df[success_df['tool_name'] == selected_tool], selected_tool, success_df)
        
        elif mode == "Comparison":
            # Tool selection for comparison
            selected_tools = st.sidebar.multiselect(
                "Select tools to compare",
                success_df['tool_name'].unique(),
                default=list(success_df['tool_name'].unique())[:2]
            )
            if len(selected_tools) < 2:
                st.error("Please select at least two tools for comparison")
                return
            
            comparison_analysis(success_df, selected_tools)
        
        else:  # Heatmap mode
            category_df = categorize_measurements(data_by_tool)
            plot_category_heatmap(category_df)
        
    except Exception as e:
        st.error(f"Error processing data: {str(e)}")

if __name__ == "__main__":
    main()