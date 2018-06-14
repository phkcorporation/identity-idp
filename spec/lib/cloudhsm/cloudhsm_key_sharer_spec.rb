require 'rails_helper'
require 'cloudhsm/cloudhsm_key_sharer'

describe CloudhsmKeySharer do
  let(:saml_label) { 'saml_20180614001957' }
  let(:subject) { CloudhsmKeySharer.new(saml_label) }
  before(:each) do
    mock_cloudhsm
    mock_input
  end

  describe '#share_saml_key' do
    it 'shares saml key and generates transcript' do
      subject.share_saml_key
      transcript = "#{saml_label}.shr"

      expect(File.exist?(transcript)).to eq(true)

      subject.cleanup
    end
  end

  describe '#cleanup' do
    it 'removes all the files if we request cleanup' do
      label = subject.share_saml_key
      subject.cleanup

      transcript = "#{label}.shr"
      expect(File.exist?(transcript)).to eq(false)
    end
  end

  def mock_cloudhsm
    allow_any_instance_of(Greenletters::Process).to receive(:wait_for).and_return(true)
    allow_any_instance_of(Greenletters::Process).to receive(:<<).and_return(true)
  end

  def mock_input
    allow(File).to receive(:read).and_return('username1:password:1234:username2')
  end
end
