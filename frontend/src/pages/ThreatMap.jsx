import { useEffect, useRef, useState } from 'react'
import * as d3 from 'd3'
import api from '../api'

const sampleGraph = {
  nodes: [
    { id: 'token-1', label: 'Phishing', threat: true },
    { id: 'token-2', label: 'Gateway', threat: false },
    { id: 'token-3', label: 'API', threat: false },
    { id: 'token-4', label: 'Suspicious', threat: true },
    { id: 'token-5', label: 'User', threat: false },
  ],
  links: [
    { source: 'token-1', target: 'token-2' },
    { source: 'token-2', target: 'token-3' },
    { source: 'token-4', target: 'token-2' },
    { source: 'token-5', target: 'token-3' },
  ],
}

export default function ThreatMap() {
  const svgRef = useRef(null)
  const [graphData, setGraphData] = useState({ nodes: [], links: [] })
  const [status, setStatus] = useState('Loading graph...')

  useEffect(() => {
    api
      .get('/graph')
      .then((res) => {
        setGraphData(res.data)
        setStatus('Threat map loaded')
      })
      .catch(() => {
        setGraphData(sampleGraph)
        setStatus('Using local threat sample')
      })
  }, [])

  useEffect(() => {
    if (!svgRef.current) return

    const nodes = graphData.nodes.length ? graphData.nodes : sampleGraph.nodes
    const links = graphData.links?.length ? graphData.links : graphData.edges?.length ? graphData.edges : sampleGraph.links

    const width = 760
    const height = 560
    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()

    const link = svg
      .append('g')
      .attr('stroke', 'rgba(148, 163, 184, 0.35)')
      .attr('stroke-width', 1.5)
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke-linecap', 'round')
      .attr('opacity', 0.75)

    const simulation = d3
      .forceSimulation(nodes)
      .force('link', d3.forceLink(links).id((d) => d.id).distance(120).strength(0.7))
      .force('charge', d3.forceManyBody().strength(-220))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collide', d3.forceCollide(28))

    const node = svg
      .append('g')
      .selectAll('circle')
      .data(nodes)
      .join('circle')
      .attr('r', 14)
      .attr('fill', (d) => (d.threat ? '#fb923c' : '#38bdf8'))
      .attr('stroke', '#0f172a')
      .attr('stroke-width', 2)
      .call(drag(simulation))

    const label = svg
      .append('g')
      .selectAll('text')
      .data(nodes)
      .join('text')
      .text((d) => d.label)
      .attr('font-size', 10)
      .attr('fill', '#cbd5e1')
      .attr('dx', 18)
      .attr('dy', 4)

    const signalMarker = svg
      .append('g')
      .selectAll('circle')
      .data(links)
      .join('circle')
      .attr('r', 5)
      .attr('fill', '#34d399')
      .attr('opacity', 0.9)

    simulation.on('tick', () => {
      link
        .attr('x1', (d) => d.source.x)
        .attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x)
        .attr('y2', (d) => d.target.y)

      node.attr('cx', (d) => d.x).attr('cy', (d) => d.y)
      label.attr('x', (d) => d.x).attr('y', (d) => d.y)
    })

    const timer = d3.timer((elapsed) => {
      signalMarker.attr('cx', (d, i) => {
        const t = ((elapsed / 1200) + i * 0.25) % 1
        return d.source.x + (d.target.x - d.source.x) * t
      })
      signalMarker.attr('cy', (d, i) => {
        const t = ((elapsed / 1200) + i * 0.25) % 1
        return d.source.y + (d.target.y - d.source.y) * t
      })
    })

    function drag(simulation) {
      function dragstarted(event) {
        if (!event.active) simulation.alphaTarget(0.3).restart()
        event.subject.fx = event.subject.x
        event.subject.fy = event.subject.y
      }

      function dragged(event) {
        event.subject.fx = event.x
        event.subject.fy = event.y
      }

      function dragended(event) {
        if (!event.active) simulation.alphaTarget(0)
        event.subject.fx = null
        event.subject.fy = null
      }

      return d3.drag().on('start', dragstarted).on('drag', dragged).on('end', dragended)
    }

    return () => {
      simulation.stop()
      timer.stop()
    }
  }, [graphData])

  return (
    <div className="grid gap-6 lg:grid-cols-[1.7fr_0.9fr]">
      <section className="rounded-3xl border border-white/10 bg-slate-900/70 p-8 shadow-xl shadow-slate-950/20">
        <div className="mb-6 flex items-center justify-between gap-4">
          <div>
            <p className="text-sm uppercase tracking-[0.25em] text-gray-400">Threat map</p>
            <h1 className="mt-2 text-3xl font-semibold text-white">Token network analysis</h1>
          </div>
          <span className="rounded-full bg-emerald-500/15 px-4 py-2 text-xs uppercase tracking-wide text-emerald-300">{status}</span>
        </div>

        <div className="h-[560px] rounded-3xl bg-slate-950/80 p-4">
          <svg ref={svgRef} width="100%" height="100%" viewBox="0 0 760 560" />
        </div>
      </section>

      <aside className="space-y-6 rounded-3xl border border-white/10 bg-slate-900/70 p-8 shadow-xl shadow-slate-950/20">
        <div>
          <p className="text-sm uppercase tracking-[0.25em] text-gray-400">Observation</p>
          <h2 className="mt-2 text-2xl font-semibold text-white">Suspicious clusters</h2>
        </div>
        <div className="space-y-4 text-sm leading-6 text-gray-300">
          <p>The interactive threat map reveals token flows and moving signal nodes to show suspicious activity across the network.</p>
          <p>Drag the nodes to explore how the system clusters threats and normal traffic.</p>
        </div>
      </aside>
    </div>
  )
}
