defmodule COSETest.Mac0Test do
  use ExUnit.Case

  alias COSE.Messages.Mac0
  alias COSE.Keys.Symmetric

  test "roundtrip" do
    msg_phdr = %{alg: :aes_ccm_16_64_128}

    msg_uhdr = %{
      iv: COSE.tag_as_byte(<<222, 100, 52, 107, 249, 208, 239, 101, 73, 73, 196, 224>>)
    }

    msg = Mac0.build("content to mac", msg_phdr, msg_uhdr)

    key = %Symmetric{k: <<0>>}

    encoded = Mac0.mac_encode(msg, :sha256, key)

    assert {:ok, decoded} = Mac0.verify_decode(encoded, :sha256, key)
    assert decoded.tag
    assert decoded.payload == msg.payload
  end
end
