require 'rails_helper'

describe UspsExporter do
  let(:export_file) { Tempfile.new('usps_export.psv') }
  let(:otp) { 'ABC123' }
  let(:pii_attributes) do
    Pii::Attributes.new_from_hash(
      first_name: 'Söme',
      last_name: 'Öne',
      address1: '123 Añy St',
      address2: 'Sté 123',
      city: 'Sömewhere',
      state: 'KS',
      zipcode: '66666-1234'
    )
  end
  let(:service_provider) { ServiceProvider.from_issuer('http://localhost:3000') }
  let(:psv_row_contents) do
    now = Time.zone.now
    due = now + UspsExporter::OTP_MAX_VALID_DAYS.days
    current_date = now.strftime('%-B %-e')
    due_date = due.strftime('%-B %-e')
    values = [
      UspsExporter::CONTENT_ROW_ID,
      pii_attributes.first_name + ' ' + pii_attributes.last_name,
      pii_attributes.address1,
      pii_attributes.address2,
      pii_attributes.city,
      pii_attributes.state,
      pii_attributes.zipcode,
      otp,
      "#{current_date}, #{now.year}",
      "#{due_date}, #{due.year}",
      service_provider.friendly_name,
      service_provider.return_to_sp_url,
    ]
    values.join('|')
  end

  subject { described_class.new(export_file.path) }

  after do
    export_file.close
    export_file.unlink
  end

  describe '#run' do
    before do
      confirmation_maker = UspsConfirmationMaker.new(
        pii: pii_attributes,
        issuer: service_provider.issuer,
        profile: build(:profile)
      )
      allow(confirmation_maker).to receive(:otp).and_return(otp)
      confirmation_maker.perform
    end

    it 'creates plain text file' do
      subject.run

      psv_contents = export_file.read

      expect(psv_contents).to eq("01|1\r\n#{psv_row_contents}\r\n")
    end

    it 'clears entries after creating file' do
      expect(UspsConfirmation.count).to eq 1

      subject.run

      expect(UspsConfirmation.count).to eq 0
    end
  end
end
