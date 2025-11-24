defmodule COSE.Keys.RSA do
  defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :n, :e, :d, :p, :q, :dp, :dq, :qi]

  @public_exponent 65_537

  @doc """
  Generates an RSA key pair for the given algorithm.
  Strict FDO Base Profile Support:
    - :rs256 -> 2048-bit key, SHA-256, PKCS#1 v1.5
    - :rs384 -> 3072-bit key, SHA-384, PKCS#1 v1.5
  """
  def generate(alg) do
    bits = bits(alg)

    {_pub, priv} =
      :crypto.generate_key(:rsa, {bits, @public_exponent})

    [e, n, d, p, q, dp, dq, qi] = priv

    %__MODULE__{
      kty: :rsa,
      alg: alg,
      n: n,
      e: e,
      d: d,
      p: p,
      q: q,
      dp: dp,
      dq: dq,
      qi: qi
    }
  end

  defp bits(:rs256), do: 2048
  defp bits(:rs384), do: 3072

  def digest_type(key) do
    case key.alg do
      :rs256 -> :sha256
      :rs384 -> :sha384
    end
  end
end

defimpl COSE.Keys.Key, for: COSE.Keys.RSA do
  alias COSE.Keys.RSA

  def sign(key, to_be_signed) do
    digest = RSA.digest_type(key)

    private_key =
      [key.e, key.n, key.d]

    :crypto.sign(:rsa, digest, to_be_signed, private_key, [])
    |> COSE.tag_as_byte()
  end

  def verify(key, to_be_verified, signature) do
    digest = RSA.digest_type(key)
    public_key = [key.e, key.n]

    :crypto.verify(:rsa, digest, to_be_verified, signature, public_key, [])
  end
end
