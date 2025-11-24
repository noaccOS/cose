defmodule COSE.Keys.ECC do
  defstruct [:kty, :kid, :alg, :key_ops, :base_iv, :crv, :x, :y, :d]

  @doc """
  Generates a key for the specified algorithm.
  Supported: :es256 (P-256), :es384 (P-384)
  """
  def generate(alg) do
    {curve, cose_crv, key_len} = get_curve_info(alg)
    {pub, priv} = :crypto.generate_key(:ecdh, curve)

    <<4, x::binary-size(key_len), y::binary-size(key_len)>> = pub

    %__MODULE__{
      kty: :ecc,
      crv: cose_crv,
      alg: alg,
      x: x,
      y: y,
      d: priv
    }
  end

  def digest_type(key) do
    case key.alg do
      :es256 -> :sha256
      :es384 -> :sha384
    end
  end

  def curve(key) do
    case key.alg do
      :es256 -> :prime256v1
      :es384 -> :secp384r1
    end
  end

  def public_key(key) do
    <<4, key.x::binary, key.y::binary>>
  end

  defp get_curve_info(:es256), do: {:prime256v1, :p256, 32}
  defp get_curve_info(:es384), do: {:secp384r1, :p384, 48}
end

defimpl COSE.Keys.Key, for: COSE.Keys.ECC do
  alias COSE.Keys.ECC

  def sign(key, to_be_signed) do
    curve = ECC.curve(key)
    digest_type = ECC.digest_type(key)

    :crypto.sign(:ecdsa, digest_type, to_be_signed, [key.d, curve])
    |> COSE.tag_as_byte()
  end

  def verify(ver_key, to_be_verified, signature) do
    digest_type = ECC.digest_type(ver_key)
    curve = ECC.curve(ver_key)
    pub_key_bin = ECC.public_key(ver_key)

    :crypto.verify(:ecdsa, digest_type, to_be_verified, signature, [pub_key_bin, curve])
  end
end
