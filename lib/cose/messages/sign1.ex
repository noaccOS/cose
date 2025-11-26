defmodule COSE.Messages.Sign1 do
  alias COSE.Keys

  defstruct [:phdr, :uhdr, :payload, :signature]

  @spec build(binary, map, map) :: map
  def build(payload, phdr \\ %{}, uhdr \\ %{}) do
    %__MODULE__{phdr: phdr, uhdr: uhdr, payload: COSE.tag_as_byte(payload)}
  end

  def sign_encode(msg, key) do
    msg = sign(msg, key)

    value = [
      COSE.Headers.tag_phdr(msg.phdr),
      msg.uhdr,
      msg.payload,
      msg.signature
    ]

    CBOR.encode(%CBOR.Tag{tag: 18, value: value})
  end

  def sign(msg, key, external_aad \\ <<>>) do
    to_be_signed = CBOR.encode(sig_structure(msg, external_aad))

    %__MODULE__{
      msg
      | signature: Keys.sign(key, to_be_signed)
    }
  end

  def verify_decode(encoded_msg, key) do
    with {:ok, msg} <- decode(encoded_msg) do
      if verify(msg, key) do
        {:ok, msg}
      else
        :error
      end
    end
  end

  def decode(encoded_msg) do
    case CBOR.decode(encoded_msg) do
      {:ok, %CBOR.Tag{tag: 18, value: [phdr, uhdr, payload, signature]}, _} ->
        decoded = %__MODULE__{
          phdr: COSE.Headers.decode_phdr(phdr),
          uhdr: uhdr,
          payload: payload,
          signature: signature
        }

        {:ok, decoded}

      _ ->
        :error
    end
  end

  def verify(msg, ver_key, external_aad \\ <<>>) do
    to_be_verified = CBOR.encode(sig_structure(msg, external_aad))
    %CBOR.Tag{tag: :bytes, value: signature} = msg.signature

    if Keys.verify(ver_key, to_be_verified, signature) do
      msg
    else
      false
    end
  end

  def sig_structure(msg, external_aad \\ <<>>) do
    [
      "Signature1",
      (msg.phdr == %{} && <<>>) || COSE.Headers.tag_phdr(msg.phdr),
      COSE.tag_as_byte(external_aad),
      msg.payload
    ]
  end
end
