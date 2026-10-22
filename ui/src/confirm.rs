//! A modal asking to confirm an action, opened in the backdrop.

use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct ConfirmDialogProps {
    pub title: String,
    /// The label of the confirming button.
    pub confirm: AttrValue,
    /// Show the confirming button as dangerous, e.g. for a deletion.
    #[prop_or_default]
    pub danger: bool,
    pub on_confirm: Callback<()>,
    #[prop_or_default]
    pub children: Html,
}

#[function_component(ConfirmDialog)]
pub fn confirm_dialog(props: &ConfirmDialogProps) -> Html {
    #[allow(clippy::expect_used)]
    let backdrop = use_backdrop().expect("ConfirmDialog requires BackdropViewer");
    let confirm = {
        let (backdrop, on_confirm) = (backdrop.clone(), props.on_confirm.clone());
        Callback::from(move |_: MouseEvent| {
            backdrop.close();
            on_confirm.emit(());
        })
    };
    let close = Callback::from(move |_: MouseEvent| backdrop.close());
    let variant = match props.danger {
        true => ButtonVariant::Danger,
        false => ButtonVariant::Primary,
    };
    let footer = html! {
        <>
            <Button {variant} onclick={confirm}>{ props.confirm.clone() }</Button>
            <Button variant={ButtonVariant::Link} onclick={close}>{ "Cancel" }</Button>
        </>
    };
    html! {
        <Modal title={props.title.clone()} variant={ModalVariant::Small} {footer}>
            { props.children.clone() }
        </Modal>
    }
}
