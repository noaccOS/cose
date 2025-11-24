defmodule COSE.Keys.Symmetric do
  defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :k]
end
