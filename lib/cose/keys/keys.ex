defprotocol COSE.Keys.Key do
  def sign(key, to_be_signed)
  def verify(key, to_be_verified, signature)
end

defmodule COSE.Keys do
  alias COSE.Keys.Key

  def sign(key, to_be_signed), do: Key.sign(key, to_be_signed)
  def verify(key, to_be_verified, signature), do: Key.verify(key, to_be_verified, signature)
end
