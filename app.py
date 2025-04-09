import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from fast import main as fast_main
from slow import main as slow_main
from final6 import main as final6_main
import time
from sklearn.metrics import confusion_matrix
import seaborn as sns
import matplotlib.pyplot as plt

st.set_page_config(page_title="Network Traffic Analysis", layout="wide")

def run_model(model_type):
    if model_type == "Fast Model":
        return fast_main()
    elif model_type == "Slow Model":
        return slow_main()
    else:
        return final6_main()

def create_metrics_visualization(metrics):
    # Create a bar chart for key metrics
    fig = go.Figure(data=[
        go.Bar(name='Value', x=list(metrics.keys()), y=list(metrics.values()))
    ])
    fig.update_layout(
        title='Model Performance Metrics',
        xaxis_title='Metric',
        yaxis_title='Value',
        showlegend=False
    )
    return fig

def create_confusion_matrix_plot(y_true, y_pred):
    cm = confusion_matrix(y_true, y_pred)
    plt.figure(figsize=(10, 8))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title('Confusion Matrix')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    return plt

def main():
    st.title("Network Intrusion Detection System Dashboard")
    st.write("Select a model to analyze network traffic patterns")

    # Create three columns for the model selection buttons
    col1, col2, col3 = st.columns(3)

    with col1:
        if st.button("Dual-Model", use_container_width=True):
            st.session_state['selected_model'] = "Dual-Model"
    
    with col2:
        if st.button("Fast Model", use_container_width=True):
            st.session_state['selected_model'] = "Fast Model"
    
    with col3:
        if st.button("Slow Model", use_container_width=True):
            st.session_state['selected_model'] = "Slow Model"

    if 'selected_model' in st.session_state:
        st.write(f"Running {st.session_state['selected_model']}...")
        
        # Create a progress bar
        progress_bar = st.progress(0)
        
        # Run the selected model
        with st.spinner('Replaying Testing dataset as live packet stream...'):
            results = run_model(st.session_state['selected_model'])
            progress_bar.progress(100)

        # Display results in tabs
        tab1, tab2, tab3 = st.tabs(["Metrics", "Confusion Matrix", "Detailed Analysis"])

        with tab1:
            st.subheader("Model Performance Metrics")
            metrics = {
                'Accuracy': results['accuracy'],
                'F1 Score': results['f1'],
                'Average Latency (ms)': results['avg_latency'] * 1000,
                'Packets/Second': results['packets_per_second'],
                'Flow Miss Rate': results['flow_miss_rate']
            }
            st.plotly_chart(create_metrics_visualization(metrics))

        with tab2:
            st.subheader("Confusion Matrix")
            fig = create_confusion_matrix_plot(results['true_labels'], results['predicted_labels'])
            st.pyplot(fig)

        with tab3:
            st.subheader("Detailed Analysis")
            col1, col2, col3 = st.columns(3)
            
            with col1:
                st.write("Models Overview")
                st.write(f"Model Type: Fast Model")
                st.write(f"F1 Score: {results['f1_fast']}")
                st.write(f"Accuracy: {results['accuracy_fast']}")
                st.write(f"Model Type: Slow Model")
                st.write(f"F1 Score: {results['f1_slow']}")
                st.write(f"Accuracy: {results['accuracy_slow']}")

            with col2:
                st.write("Dual-Model Statistics")
                st.write(f"Total Packets Processed: {results['total_packets']}")
                st.write(f"Average Latency per Packet: {results['avg_latency']}")
                st.write(f"Packets Processed per Second: {results['packets_per_second']}")
                st.write(f"Fast Model Usage: {results['fast_model_count']}")
                st.write(f"Slow Model Usage: {results['slow_model_count']}")
                st.write(f"Average Confidence: {results['avg_confidence']:.2f}")
                st.write(f"Confidence Threshold: {results['confidence_threshold']:.2f}")
            
            with col3:
                st.write("Performance Metrics")
                st.write(f"Service Rate(classifications per second): {results['packets_per_second']:.2f}")
                st.write(f"End-to-End Latency: {results['avg_latency'] * 1000:.2f} ms")
                st.write(f"3-Packet Flow Miss Rate: {results['flow_miss_rate']:.4f}")
                st.write(f"Packet predicted as Intusion : {results['intrusion_count']}")
                st.write(f"F1 Score: {results['f1']}")
                st.write(f"Accuracy: {results['accuracy']}")

if __name__ == "__main__":
    main() 