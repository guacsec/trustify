use crate::{ingest::ingest_file, model::IngestResult};
use gloo_file::{File, FileList};
use gloo_timers::callback::Timeout;
use patternfly_yew::prelude::*;
use std::{collections::VecDeque, rc::Rc, time::Duration};
use wasm_bindgen_futures::spawn_local;
use web_sys::{DragEvent, HtmlInputElement};
use yew::prelude::*;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(Clone, Default, PartialEq)]
struct IngestionProgress {
    busy: bool,
    completed: usize,
    total: usize,
    current: Option<String>,
}

/// The synchronous queue owns the worker flag, so rapid drops cannot start two workers.
struct IngestionQueue<T> {
    pending: VecDeque<(String, T)>,
    progress: IngestionProgress,
}

impl<T> Default for IngestionQueue<T> {
    fn default() -> Self {
        Self {
            pending: VecDeque::new(),
            progress: IngestionProgress::default(),
        }
    }
}

impl<T> IngestionQueue<T> {
    /// Return whether the caller must start the worker.
    fn enqueue(&mut self, files: Vec<(String, T)>) -> bool {
        if files.is_empty() {
            return false;
        }
        let start_worker = !self.progress.busy;
        if start_worker {
            self.progress = IngestionProgress {
                busy: true,
                ..Default::default()
            };
        }
        self.progress.total += files.len();
        self.pending.extend(files);
        start_worker
    }

    fn next(&mut self) -> Option<(String, T)> {
        let next = self.pending.pop_front();
        self.progress.current = next.as_ref().map(|(name, _)| name.clone());
        if next.is_none() {
            self.progress.busy = false;
        }
        next
    }

    fn complete(&mut self) {
        self.progress.completed += 1;
        self.progress.current = None;
    }
}

#[derive(Clone, PartialEq)]
struct IngestionContext {
    progress: IngestionProgress,
    enqueue: Callback<Vec<File>>,
}

#[derive(Default)]
struct Notifications {
    next_id: usize,
    entries: Vec<(usize, Toast)>,
}

enum NotificationAction {
    Show(Vec<Toast>),
    Close(usize),
}

impl Reducible for Notifications {
    type Action = NotificationAction;

    fn reduce(self: Rc<Self>, action: Self::Action) -> Rc<Self> {
        let mut entries = self.entries.clone();
        let mut next_id = self.next_id;
        match action {
            NotificationAction::Show(toasts) => {
                for toast in toasts {
                    entries.push((next_id, toast));
                    next_id += 1;
                }
            }
            NotificationAction::Close(id) => entries.retain(|(entry_id, _)| *entry_id != id),
        }
        Rc::new(Self { next_id, entries })
    }
}

#[derive(PartialEq, Properties)]
struct AutoDismissProps {
    id: usize,
    timeout: Option<Duration>,
    onclose: Callback<usize>,
}

/// PatternFly's ToastViewer only adds close buttons to untimed toasts.
/// Keep upload alerts closable while also expiring successful ones.
#[function_component(AutoDismiss)]
fn auto_dismiss(props: &AutoDismissProps) -> Html {
    let onclose = use_callback((props.id, props.onclose.clone()), |(), (id, onclose)| {
        onclose.emit(*id);
    });
    {
        let onclose = onclose.clone();
        use_effect_with(props.timeout, move |timeout| {
            let timer = timeout
                .map(|timeout| Timeout::new(timeout.as_millis() as u32, move || onclose.emit(())));
            move || drop(timer)
        });
    }
    Html::default()
}

#[derive(PartialEq, Properties)]
pub struct IngestionProviderProps {
    pub children: Children,
}

/// Mounted above the route switch so navigation never owns the upload lifecycle.
#[function_component(IngestionProvider)]
pub fn ingestion_provider(props: &IngestionProviderProps) -> Html {
    let queue = use_mut_ref(IngestionQueue::<File>::default);
    let progress = use_state(IngestionProgress::default);
    let latest_token = use_latest_access_token();
    let notifications = use_reducer(Notifications::default);
    let onclose = {
        let notifications = notifications.dispatcher();
        Callback::from(move |id| notifications.dispatch(NotificationAction::Close(id)))
    };

    let enqueue = {
        let queue = queue.clone();
        let progress = progress.clone();
        let notifications = notifications.dispatcher();
        Callback::from(move |files: Vec<File>| {
            let start_worker = queue
                .borrow_mut()
                .enqueue(files.into_iter().map(|file| (file.name(), file)).collect());
            progress.set(queue.borrow().progress.clone());
            if !start_worker {
                return;
            }

            let queue = queue.clone();
            let progress = progress.clone();
            let latest_token = latest_token.clone();
            let notifications = notifications.clone();
            spawn_local(async move {
                loop {
                    let next = queue.borrow_mut().next();
                    progress.set(queue.borrow().progress.clone());
                    let Some((name, file)) = next else {
                        break;
                    };
                    let token = latest_token.as_ref().and_then(|t| t.access_token());
                    let result = ingest_file(&file, token.as_deref()).await;
                    notifications
                        .dispatch(NotificationAction::Show(outcome_toasts(&name, &result)));
                    queue.borrow_mut().complete();
                }
            });
        })
    };

    html! {
        <ContextProvider<IngestionContext> context={IngestionContext { progress: (*progress).clone(), enqueue }}>
            { for props.children.iter() }
            <AlertGroup toast=true>
                { for notifications.entries.iter().map(|(id, toast)| {
                    let close = onclose.clone();
                    let toast_id = *id;
                    html_nested! {
                        <Alert key={*id} title={toast.title.clone()} r#type={toast.r#type}
                            onclose={Some(Callback::from(move |()| close.emit(toast_id)))}>
                            <AutoDismiss id={*id} timeout={toast.timeout} onclose={onclose.clone()} />
                            { toast.body.clone() }
                        </Alert>
                    }
                }) }
            </AlertGroup>
        </ContextProvider<IngestionContext>>
    }
}

fn outcome_toasts(name: &str, result: &Result<IngestResult, String>) -> Vec<Toast> {
    match result {
        Err(error) => vec![Toast {
            title: format!("Ingestion failed: {name}"),
            r#type: AlertType::Danger,
            body: html! { <p class="trustify-break-all">{ error }</p> },
            ..Default::default()
        }],
        Ok(result) => {
            let mut toasts = vec![Toast {
                title: if result.duplicate {
                    format!("Document already exists: {name}")
                } else {
                    format!("Document ingested: {name}")
                },
                r#type: if result.duplicate {
                    AlertType::Info
                } else {
                    AlertType::Success
                },
                timeout: Some(Duration::from_secs(5)),
                body: html! {
                    <div class="trustify-break-all">
                        <p>{ format!("ID: {}", result.id) }</p>
                        if let Some(document_id) = &result.document_id {
                            <p>{ format!("Document ID: {document_id}") }</p>
                        }
                    </div>
                },
                ..Default::default()
            }];
            if !result.warnings.is_empty() {
                toasts.push(Toast {
                    title: format!("Warnings: {name}"),
                    r#type: AlertType::Warning,
                    body: html! {
                        <ul class="trustify-break-all">
                            { for result.warnings.iter().map(|warning| html! { <li>{ warning }</li> }) }
                        </ul>
                    },
                    ..Default::default()
                });
            }
            toasts
        }
    }
}

fn is_file_drag(event: &DragEvent) -> bool {
    event.data_transfer().is_some_and(|transfer| {
        transfer
            .types()
            .iter()
            .any(|kind| kind.as_string().as_deref() == Some("Files"))
    })
}

#[function_component(IngestDropZone)]
pub fn ingest_drop_zone() -> Html {
    let context =
        use_context::<IngestionContext>().expect("IngestDropZone requires IngestionProvider");
    let drag_over = use_state_eq(|| false);
    // Nested elements also emit enter/leave events; track depth to avoid flickering.
    let drag_depth = use_mut_ref(|| 0usize);
    let input_ref = use_node_ref();

    let ondragenter = {
        let drag_depth = drag_depth.clone();
        let drag_over = drag_over.clone();
        Callback::from(move |event: DragEvent| {
            if is_file_drag(&event) {
                event.prevent_default();
                event.stop_propagation();
                *drag_depth.borrow_mut() += 1;
                drag_over.set(true);
            }
        })
    };
    let ondragover = Callback::from(move |event: DragEvent| {
        if is_file_drag(&event) {
            event.prevent_default();
            event.stop_propagation();
            if let Some(transfer) = event.data_transfer() {
                transfer.set_drop_effect("copy");
            }
        }
    });
    let ondragleave = {
        let drag_depth = drag_depth.clone();
        let drag_over = drag_over.clone();
        Callback::from(move |event: DragEvent| {
            event.stop_propagation();
            let mut depth = drag_depth.borrow_mut();
            *depth = depth.saturating_sub(1);
            if *depth == 0 {
                drag_over.set(false);
            }
        })
    };
    let ondrop = {
        let drag_over = drag_over.clone();
        let enqueue = context.enqueue.clone();
        Callback::from(move |event: DragEvent| {
            event.prevent_default();
            event.stop_propagation();
            *drag_depth.borrow_mut() = 0;
            drag_over.set(false);
            if let Some(files) = event.data_transfer().and_then(|transfer| transfer.files()) {
                enqueue.emit(FileList::from(files).iter().cloned().collect());
            }
        })
    };
    let onchange = {
        let enqueue = context.enqueue.clone();
        Callback::from(move |event: Event| {
            let input: HtmlInputElement = event.target_unchecked_into();
            if let Some(files) = input.files() {
                enqueue.emit(FileList::from(files).iter().cloned().collect());
            }
            input.set_value("");
        })
    };
    let onclick = {
        let input_ref = input_ref.clone();
        Callback::from(move |_: MouseEvent| {
            if let Some(input) = input_ref.cast::<HtmlInputElement>() {
                input.click();
            }
        })
    };

    let progress = &context.progress;
    html! {
        <section
            class={classes!("trustify-ingest-drop", (*drag_over).then_some("trustify-ingest-drop--drag-over"))}
            aria-label="Ingest documents"
            aria-busy={progress.busy.to_string()}
            {ondragenter} {ondragover} {ondragleave} {ondrop}
        >
            <p class="trustify-ingest-drop__hint">{ if progress.busy { "Drop to queue" } else { "Drop to ingest" } }</p>
            <input ref={input_ref} type="file" multiple=true {onchange} hidden=true />
            <Button variant={ButtonVariant::Plain} class="trustify-ingest-drop__browse" label="Browse files" {onclick} />
            <div aria-live="polite" aria-atomic="true">
                if progress.busy {
                    <div class="trustify-ingest-drop__current">
                        <Spinner size={SpinnerSize::Sm} />
                        <span title={progress.current.clone()}>{ format!("Ingesting {}", progress.current.as_deref().unwrap_or("documents…")) }</span>
                    </div>
                    <Progress
                        id="global-ingest-progress"
                        size={ProgressSize::Small}
                        value={progress.completed as f64 / progress.total as f64}
                        description={format!("{} of {} documents processed", progress.completed, progress.total)}
                        location={ProgressMeasureLocation::None}
                    />
                }
            </div>
        </section>
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(names: &[&str]) -> Vec<(String, ())> {
        names.iter().map(|name| (name.to_string(), ())).collect()
    }

    #[test]
    fn drops_extend_the_queue_without_starting_another_worker() {
        let mut queue = IngestionQueue::default();
        assert!(!queue.enqueue(files(&[])));
        assert!(!queue.progress.busy);
        assert!(queue.enqueue(files(&["one", "two"])));
        assert_eq!(queue.next().unwrap().0, "one");
        assert!(!queue.enqueue(files(&["three", "four"])));
        assert_eq!(queue.progress.current.as_deref(), Some("one"));
        assert_eq!(queue.progress.total, 4);
        queue.complete();
        for (index, name) in ["two", "three", "four"].iter().enumerate() {
            assert_eq!(queue.next().unwrap().0, *name);
            assert_eq!(queue.progress.completed, index + 1);
            queue.complete();
        }
        assert!(queue.next().is_none());
        assert!(!queue.progress.busy);
        assert_eq!(queue.progress.completed, 4);
        assert!(queue.progress.current.is_none());
        assert!(queue.enqueue(files(&["five"])));
        assert_eq!(queue.progress.total, 1);
        assert_eq!(queue.progress.completed, 0);
    }

    #[test]
    fn empty_drops_do_not_change_an_active_queue() {
        let mut queue = IngestionQueue::default();
        queue.enqueue(files(&["one"]));
        queue.next();
        assert!(!queue.enqueue(files(&[])));
        assert!(queue.progress.busy);
        assert_eq!(queue.progress.total, 1);
        assert_eq!(queue.progress.current.as_deref(), Some("one"));
    }

    #[test]
    fn mixed_outcomes_complete_all_attempts_and_allow_retry() {
        let mut queue = IngestionQueue::default();
        queue.enqueue(files(&["success", "read failure", "upload failure"]));
        let outcomes = [
            Ok(ingested(false)),
            Err("read failure".into()),
            Err("upload failure".into()),
        ];
        for outcome in outcomes {
            let (name, _) = queue.next().unwrap();
            assert!(!outcome_toasts(&name, &outcome).is_empty());
            queue.complete();
        }
        assert!(queue.next().is_none());
        assert_eq!(queue.progress.completed, 3);
        assert!(queue.enqueue(files(&["read failure"])));
        assert_eq!(queue.next().unwrap().0, "read failure");
        queue.complete();
        assert!(queue.next().is_none());
        assert_eq!(queue.progress.completed, 1);
    }

    fn ingested(duplicate: bool) -> IngestResult {
        IngestResult {
            id: "document-id".into(),
            document_id: None,
            duplicate,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn closing_toasts_is_independent_and_does_not_reuse_ids() {
        let state = Rc::new(Notifications::default());
        let state = state.reduce(NotificationAction::Show(outcome_toasts(
            "one.json",
            &Ok(ingested(false)),
        )));
        let state = state.reduce(NotificationAction::Show(outcome_toasts(
            "failure.json",
            &Err("Failed to upload".into()),
        )));
        assert_eq!(state.entries.len(), 2);
        let state = state.reduce(NotificationAction::Close(0));
        assert_eq!(state.entries.len(), 1);
        assert_eq!(state.entries[0].0, 1);
        // An already-closed toast's timer must not dismiss any other notification.
        let state = state.reduce(NotificationAction::Close(0));
        assert_eq!(state.entries.len(), 1);
        let state = state.reduce(NotificationAction::Show(outcome_toasts(
            "two.json",
            &Ok(ingested(false)),
        )));
        assert_eq!(state.entries[1].0, 2);
        let state = state.reduce(NotificationAction::Close(1));
        let state = state.reduce(NotificationAction::Close(2));
        assert!(state.entries.is_empty());
    }

    #[test]
    fn successes_and_duplicates_expire_but_errors_and_warnings_persist() {
        for (duplicate, kind) in [(false, AlertType::Success), (true, AlertType::Info)] {
            let mut result = ingested(duplicate);
            result.warnings.push("Check this document".into());
            let toasts = outcome_toasts("document.json", &Ok(result));
            assert_eq!(toasts.len(), 2);
            assert_eq!(toasts[0].r#type, kind);
            assert!(toasts[0].title.contains("document.json"));
            assert_eq!(toasts[0].timeout, Some(Duration::from_secs(5)));
            assert_eq!(toasts[1].r#type, AlertType::Warning);
            assert_eq!(toasts[1].timeout, None);
        }
        let toasts = outcome_toasts("invalid.json", &Err("Unsupported format".into()));
        assert_eq!(toasts.len(), 1);
        assert_eq!(toasts[0].r#type, AlertType::Danger);
        assert!(toasts[0].title.contains("invalid.json"));
        assert_eq!(toasts[0].timeout, None);
    }
}
