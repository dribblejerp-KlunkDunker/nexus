"""
Vectorized NEAT feed-forward evaluation.

neat-python's FeedForwardNetwork.activate() handles one sample per call in pure
Python. Scoring a 150-genome population against 20k vectors that way is ~3M
interpreter round-trips per generation, which is what the Ray fan-out in
train_for_real.py was buying its way out of.

Replaying the same node_evals schedule with numpy over the whole batch gives the
identical result two orders of magnitude faster, on one core. Parallelism is
then a choice rather than a requirement.
"""

import numpy as np
import neat


def _sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.clip(5.0 * z, -60.0, 60.0)))


ACTIVATIONS = {
    "sigmoid": _sigmoid,
    "tanh": lambda z: np.tanh(np.clip(2.5 * z, -60.0, 60.0)),
    "relu": lambda z: np.maximum(z, 0.0),
    "identity": lambda z: z,
    "clamped": lambda z: np.clip(z, -1.0, 1.0),
    "abs": np.abs,
    "gauss": lambda z: np.exp(-5.0 * np.clip(z, -3.4, 3.4) ** 2),
    "sin": lambda z: np.sin(np.clip(5.0 * z, -60.0, 60.0)),
    "square": lambda z: z ** 2,
    "cube": lambda z: z ** 3,
    "log": lambda z: np.log(np.maximum(z, 1e-7)),
    "exp": lambda z: np.exp(np.clip(z, -60.0, 60.0)),
    "hat": lambda z: np.maximum(0.0, 1.0 - np.abs(z)),
    "inv": lambda z: 1.0 / np.where(np.abs(z) < 1e-7, 1e-7, z),
}

AGGREGATIONS = {
    "sum": lambda parts: np.sum(parts, axis=0),
    "product": lambda parts: np.prod(parts, axis=0),
    "max": lambda parts: np.max(parts, axis=0),
    "min": lambda parts: np.min(parts, axis=0),
    "maxabs": lambda parts: parts[np.argmax(np.abs(parts), axis=0), np.arange(parts.shape[1])],
    "mean": lambda parts: np.mean(parts, axis=0),
    "median": lambda parts: np.median(parts, axis=0),
}


def activate_batch(genome, config, X: np.ndarray) -> np.ndarray:
    """Scores an (N, D) matrix through a NEAT genome. Returns (N,) outputs.

    Falls back to neat-python's own evaluator for any activation or aggregation
    function without a vector form, so results never silently diverge.
    """
    net = neat.nn.FeedForwardNetwork.create(genome, config)
    n = X.shape[0]

    values = {}
    for i, key in enumerate(net.input_nodes):
        values[key] = X[:, i].astype(np.float64)
    for key in net.output_nodes:
        values[key] = np.zeros(n, dtype=np.float64)

    for node, act_name, agg_name, bias, response, links in net.node_evals:
        act = ACTIVATIONS.get(getattr(act_name, "__name__", str(act_name)).replace("_activation", ""))
        agg = AGGREGATIONS.get(getattr(agg_name, "__name__", str(agg_name)).replace("_aggregation", ""))
        if act is None or agg is None:
            return np.array([net.activate(row)[0] for row in X], dtype=np.float64)

        if links:
            parts = np.empty((len(links), n), dtype=np.float64)
            for j, (src, weight) in enumerate(links):
                parts[j] = values.get(src, np.zeros(n)) * weight
            s = agg(parts)
        else:
            s = np.zeros(n, dtype=np.float64)
        values[node] = act(bias + response * s)

    return values[net.output_nodes[0]]
