import json
import sys
from pathlib import Path

import streamlit as st


ROOT = Path(__file__).resolve().parent
AI_ROOT = ROOT / "Ai"
if str(AI_ROOT) not in sys.path:
    sys.path.insert(0, str(AI_ROOT))

from rag.core.pipeline import RAGPipeline


st.set_page_config(page_title="ARGUS RAG Playground", layout="wide")
st.title("ARGUS RAG Playground")
st.caption("Query the local RAG index, optional Gemini answers, and Redis-backed chat memory.")


@st.cache_resource
def get_pipeline() -> RAGPipeline:
    return RAGPipeline(enable_retrieval=True, enable_llm=True)


pipeline = get_pipeline()

with st.sidebar:
    st.header("Session")
    session_id = st.text_input("Session ID", value="demo")
    if st.button("Clear memory", use_container_width=True):
        pipeline.memory.clear(session_id)
        st.success(f"Cleared memory for {session_id}")
    st.json(pipeline.memory.stats(session_id))


query = st.text_area(
    "Enter your SOC / RAG query",
    placeholder="Example: Explain brute-force SSH behavior and the likely MITRE ATT&CK technique.",
    height=140,
)

top_k = st.slider("Top K references", min_value=1, max_value=10, value=5)

if st.button("Generate answer", type="primary", use_container_width=True):
    with st.spinner("Retrieving context and generating answer..."):
        result = pipeline.answer_query(query=query, session_id=session_id, top_k=top_k)

    st.subheader("Answer")
    st.write(result["answer"])

    st.subheader("Retrieved References")
    if not result["rag_chunks"]:
        st.info("No RAG references returned.")
    else:
        for index, chunk in enumerate(result["rag_chunks"], 1):
            metadata = chunk.get("metadata", {}) or {}
            label = metadata.get("technique_id") or metadata.get("rule_id") or metadata.get("file") or f"reference-{index}"
            with st.expander(f"{index}. {label}", expanded=False):
                st.caption(json.dumps(metadata, indent=2))
                st.write(chunk.get("text", ""))

    st.subheader("Memory")
    st.json(result["history"])

st.markdown(
    "Run with `streamlit run D:\\analyst\\rag_streamlit.py` after installing dependencies and, "
    "if desired, starting Redis."
)
